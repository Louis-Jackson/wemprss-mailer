package server

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Louis-Jackson/wemprss-mailer/internal/api"
	"github.com/Louis-Jackson/wemprss-mailer/internal/qr"
)

//go:embed static/*
var embeddedStaticFS embed.FS

type sendStatus struct {
	LastAttemptAt        time.Time `json:"last_attempt_at"`
	LastSuccessAt        time.Time `json:"last_success_at"`
	LastError            string    `json:"last_error"`
	LastArticleTitle     string    `json:"last_article_title"`
	LastArticlePublished string    `json:"last_article_published"`
}

var (
	statusMu  sync.RWMutex
	lastState sendStatus
)

func withOptionalBasicAuth(next http.Handler) http.Handler {
	user := strings.TrimSpace(os.Getenv("BASIC_AUTH_USER"))
	pass := strings.TrimSpace(os.Getenv("BASIC_AUTH_PASS"))
	if user == "" && pass == "" {
		return next
	}
	required := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			w.Header().Set("WWW-Authenticate", "Basic realm=restricted")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		payload := strings.TrimPrefix(auth, "Basic ")
		if payload != required {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// StartServer starts an embedded HTTP server with static UI and APIs
func StartServer(addr string) error {
	mux := http.NewServeMux()

	// API routes
	a := api.NewAPI()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		jsonOK(w, map[string]any{
			"ok":        true,
			"service":   "wemprss-mailer",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	mux.Handle("/api/status", a.HandleStatus())

	mux.Handle("/api/refresh", a.HandleRefresh())

	mux.Handle("/api/ensure", a.HandleEnsure())

	mux.Handle("/api/send-now", a.HandleSendNow())

	// mount QR auth proxy handlers from separate module
	// 二维码代理：over 完成后触发一次发送
	mux.Handle("/api/wx/auth/qr/", qr.NewProxy("/api/wx/auth/qr/", func() string { return os.Getenv("API_BASE_URL") }))
	mux.Handle("/api/v1/wx/auth/qr/", qr.NewProxy("/api/v1/wx/auth/qr/", func() string { return os.Getenv("API_BASE_URL") }))
	// 专门处理完成扫码的回调，完成后执行一次 ensure + send，合并输出结果
	mux.HandleFunc("/api/wx/auth/qr/over", func(w http.ResponseWriter, r *http.Request) {
		overStatus, overBody, _ := qr.DoAuthenticatedGET("/api/wx/auth/qr/over", func() string { return os.Getenv("API_BASE_URL") })
		ensureOK := a.EnsureNow()

		timeout := 60 // seconds
		if v := strings.TrimSpace(os.Getenv("POST_OVER_TIMEOUT_SECONDS")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				timeout = n
			}
		}
		done := make(chan error, 1)
		go func() { done <- a.RunSendOnce() }()
		var sendErr error
		var timedOut bool
		select {
		case sendErr = <-done:
		case <-time.After(time.Duration(timeout) * time.Second):
			timedOut = true
		}

		var overParsed any
		if len(overBody) > 0 {
			var raw json.RawMessage
			if json.Unmarshal(overBody, &raw) == nil {
				overParsed = raw
			} else {
				overParsed = string(overBody)
			}
		}
		resp := map[string]any{
			"over":   map[string]any{"status": overStatus, "body": overParsed},
			"ensure": map[string]any{"ok": ensureOK},
			"send":   map[string]any{"ok": sendErr == nil && !timedOut, "timeout": timedOut, "error": errString(sendErr)},
		}
		jsonOK(w, resp)
	})
	mux.HandleFunc("/api/v1/wx/auth/qr/over", func(w http.ResponseWriter, r *http.Request) {
		overStatus, overBody, _ := qr.DoAuthenticatedGET("/api/v1/wx/auth/qr/over", func() string { return os.Getenv("API_BASE_URL") })
		ensureOK := a.EnsureNow()
		timeout := 60
		if v := strings.TrimSpace(os.Getenv("POST_OVER_TIMEOUT_SECONDS")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				timeout = n
			}
		}
		done := make(chan error, 1)
		go func() { done <- a.RunSendOnce() }()
		var sendErr error
		var timedOut bool
		select {
		case sendErr = <-done:
		case <-time.After(time.Duration(timeout) * time.Second):
			timedOut = true
		}
		var overParsed any
		if len(overBody) > 0 {
			var raw json.RawMessage
			if json.Unmarshal(overBody, &raw) == nil {
				overParsed = raw
			} else {
				overParsed = string(overBody)
			}
		}
		resp := map[string]any{
			"over":   map[string]any{"status": overStatus, "body": overParsed},
			"ensure": map[string]any{"ok": ensureOK},
			"send":   map[string]any{"ok": sendErr == nil && !timedOut, "timeout": timedOut, "error": errString(sendErr)},
		}
		jsonOK(w, resp)
	})

	// static files under embedded "static" dir
	sub, err := fs.Sub(embeddedStaticFS, "static")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("/", fileServer)

	// optional keepalive/ensure on boot
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ENSURE_ON_BOOT")), "true") {
		go func() {
			time.Sleep(2 * time.Second)
			a.EnsureNow()
		}()
	}

	// optional periodic ensure
	if secStr := strings.TrimSpace(os.Getenv("ENSURE_INTERVAL_SECONDS")); secStr != "" {
		if sec, err := strconv.Atoi(secStr); err == nil && sec > 0 {
			go func(interval time.Duration) {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for range ticker.C {
					if ok := a.EnsureNow(); !ok {
						log.Println("periodic ensure failed")
					}
				}
			}(time.Duration(sec) * time.Second)
		}
	}

	handler := withOptionalBasicAuth(mux)
	log.Printf("embedded server listening on %s\n", addr)
	return http.ListenAndServe(addr, handler)
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
