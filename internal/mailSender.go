package internal

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"time"
)

func SendMail(password, smtpHost, smtpPort, from string, to []string, subject string, body string) error {
	smtpHost = strings.TrimSpace(smtpHost)
	if smtpHost == "" {
		log.Println("send mail error: smtp host is empty")
		return fmt.Errorf("smtp host is empty")
	}

	// 基础 MIME 头（HTML 内容）
	headers := []string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", strings.Join(to, ",")),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123Z)),
	}
	msg := strings.Join(headers, "\r\n") + "\r\n\r\n" + body

	addr := net.JoinHostPort(smtpHost, smtpPort)

	if smtpPort == "465" {
		// SMTPS（隐式 TLS）
		if err := sendViaSMTPS(addr, smtpHost, from, password, to, []byte(msg)); err != nil {
			log.Println("send mail error:", err)
			return err
		}
		log.Println("send mail success")
		return nil
	}

	// 其他端口：尝试 STARTTLS，否则按明文发送（取决于服务器策略）
	if err := sendViaStartTLS(addr, smtpHost, from, password, to, []byte(msg)); err != nil {
		log.Println("send mail error:", err)
		return err
	}
	log.Println("send mail success")
	return nil
}

func sendViaSMTPS(addr, host, from, password string, to []string, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: host}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	auth := smtp.PlainAuth("", from, password, host)
	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(strings.TrimSpace(rcpt)); err != nil {
			return err
		}
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return err
	}
	_ = wc.Close()
	return client.Quit()
}

func sendViaStartTLS(addr, host, from, password string, to []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()

	// STARTTLS if supported
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{ServerName: host}
		if err := c.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	// AUTH if supported
	if ok, _ := c.Extension("AUTH"); ok {
		auth := smtp.PlainAuth("", from, password, host)
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(strings.TrimSpace(rcpt)); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return err
	}
	_ = wc.Close()
	return c.Quit()
}

// SendMailWithArticle 发送监控到的文章；若未获取到，则尝试刷新并再次监控。
// 参数说明：
// - APIUsername/APIPassword/loginURL/mpCode: 用于刷新微信文章的接口参数
// - smtpPassword/smtpHost/smtpPort/from: 邮件发送配置
// - errorRecipients/toRecipients: 告警/正常收件人
func SendMailWithArticle(APIUsername, APIPassword, loginURL, mpCode, smtpPassword, smtpHost, smtpPort, from string, errorRecipients, toRecipients []string, article MonitorResult) error {
	// 辅助函数：发送正常内容
	sendNormal := func(a MonitorResult) error {
		if len(toRecipients) == 0 {
			return fmt.Errorf("no normal recipients configured")
		}
		subject := "路透早报 自动发送-" + time.Now().Format("2006-01-02")
		return SendMail(smtpPassword, smtpHost, smtpPort, from, toRecipients, subject, a.Content)
	}

	// 辅助函数：发送错误通知
	sendError := func(msg string) error {
		if len(errorRecipients) == 0 {
			return fmt.Errorf("no error recipients configured: %s", msg)
		}
		subject := "最新文章获取失败，请检查"
		body := msg
		return SendMail(smtpPassword, smtpHost, smtpPort, from, errorRecipients, subject, body)
	}

	if article.IsNew {
		if err := sendNormal(article); err != nil {
			return err
		}
		return nil
	}

	// 未获取到新文章：尝试刷新后再次获取
	log.Println("未获取到新文章，尝试触发刷新...")
	if ok := UpdateRSS(APIUsername, APIPassword, loginURL, mpCode); !ok {
		return sendError("刷新微信文章接口调用失败")
	}
	time.Sleep(10 * time.Second)

	refreshed := Monitor()
	if refreshed.IsNew {
		if err := sendNormal(refreshed); err != nil {
			return err
		}
		return nil
	}

	// 刷新后仍未获取到
	return sendError("刷新后仍未获取到最新文章")
}
