package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 1. Load Configuration
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	cfg := TelegramConfig{
		Token:  botToken, // Assuming field name is Token in telegram.go
		ChatID: chatID,
	}

	// 2. Setup Signal Handling for Graceful Shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// 3. Start Health Check Endpoint (Crucial for Fly.io)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// 4. Start Services
	log.Printf("🦎 Chameleon Proxy starting on port %s...", port)

	// Run Telegram Server in background (it runs its own HTTP server on a separate port or same)
	// Note: If StartTelegramServer binds to :8080, you need to ensure ports don't clash.
	// Usually, Proxy uses 8080, Telegram Webhook can use 8081 or same if using paths.
	// Here we assume StartTelegramServer handles its own port or shares.
	// If they conflict, you might need to adjust ports.
	// For now, we start them. If they conflict, the second one will panic.
	go func() {
		// Try to start Telegram server on a secondary port to avoid conflict
		// Or if your telegram.go uses the same port, it might fail.
		// Let's assume Telegram webhook is handled via the Proxy or separate.
		// If your telegram.go starts a NEW gin server on ":8081", it's safe.
		// If it tries ":8080", it will crash.
		// CHECK YOUR telegram.go: Does it call r.Run(":8080")?
		// If yes, change main.go to pass a different port or merge routers.

		// For safety, let's assume we start Telegram on 8081 unless configured otherwise
		tgPort := os.Getenv("TELEGRAM_PORT")
		if tgPort == "" {
			tgPort = "8081"
		}
		StartTelegramServer(cfg, tgPort)
	}()

	StartProxy(cfg, port)

	// Wait for interrupt signal
	<-stop
	log.Println("🛑 Shutting down gracefully...")
}
