package main

import (
	"log"
	"os"
	"strings"

	"github.com/Louis-Jackson/wemprss-mailer/internal"
	srv "github.com/Louis-Jackson/wemprss-mailer/internal/server"
	"github.com/joho/godotenv" // 使用 godotenv 包加载环境变量
)

func main() {
	godotenv.Load()

	// 子命令：serve / send（默认 send 一次）
	if len(os.Args) > 1 && strings.EqualFold(os.Args[1], "serve") {
		port := strings.TrimSpace(os.Getenv("PORT"))
		if port == "" {
			port = "8080"
		}
		if err := srv.StartServer(":" + port); err != nil {
			log.Fatal(err)
		}
		return
	}

	err := internal.SendMailWithArticle(
		os.Getenv("API_USERNAME"),
		os.Getenv("API_PASSWORD"),
		os.Getenv("API_BASE_URL"),
		os.Getenv("MP_CODE"),
		os.Getenv("MAIL_PASSWORD"),
		os.Getenv("MAIL_SMTP_HOST"),
		os.Getenv("MAIL_SMTP_PORT"),
		os.Getenv("MAIL_FROM"),
		split(os.Getenv("MAIL_ERROR_TO")),
		split(os.Getenv("MAIL_TO")),
		internal.Monitor())
	if err != nil {
		log.Println("mail send failed:", err)
	}
}

func split(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var res []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}
