package main

import (
	"log"
	"os"
)

func main() {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	port := os.Getenv("LISTEN_PORT")

	if botToken == "" || chatID == "" {
		log.Println("⚠️ Warning: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.")
	}
	if port == "" {
		port = "80" // Default to 80
	}

	cfg := TelegramConfig{
		BotToken: botToken,
		ChatID:   chatID,
	}

	log.Printf("🦎 Chameleon Proxy starting on port %s...", port)
	StartProxy(cfg, port)
}
