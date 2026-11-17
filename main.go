package main

import (
	"log"
	"os"
)

func main() {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	cfg := TelegramConfig{
		BotToken: botToken,
		ChatID:   chatID,
	}

	log.Printf("🦎 Chameleon Proxy starting on port %s...", port)
	StartProxy(cfg, port)
}
