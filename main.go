package main

import (
	"log"
	"os"
)

func main() {
	// 1. Correctly load the Telegram environment variables
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")

	// 2. Render requires you to use the "PORT" environment variable
	port := os.Getenv("PORT")

	if botToken == "" || chatID == "" {
		log.Println("⚠️ Warning: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.")
	}

	// 3. Fallback to 8080 if running locally
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
