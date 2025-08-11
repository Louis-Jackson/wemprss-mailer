package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	core "github.com/Louis-Jackson/wemprss-mailer/internal"
)

type sendStatus struct {
	LastAttemptAt time.Time `json:"last_attempt_at"`
	LastSuccessAt time.Time `json:"last_success_at"`
	LastError     string    `json:"last_error"`
}

type API struct {
	mu    sync.RWMutex
	state sendStatus
}

func NewAPI() *API { return &API{} }

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(v)
}

// HandleStatus returns the last send status
func (a *API) HandleStatus() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		a.mu.RLock()
		defer a.mu.RUnlock()
		a.writeJSON(w, http.StatusOK, a.state)
	})
}

// HandleRefresh triggers an upstream refresh of WeChat articles
func (a *API) HandleRefresh() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		ok := a.EnsureNow()
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
	})
}

// HandleEnsure same as refresh for clarity in routes
func (a *API) HandleEnsure() http.Handler { return a.HandleRefresh() }

// HandleSendNow invokes sending logic immediately
func (a *API) HandleSendNow() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if err := a.RunSendOnce(); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
}

// EnsureNow calls upstream refresh API once
func (a *API) EnsureNow() bool {
	apiUser := os.Getenv("API_USERNAME")
	apiPass := os.Getenv("API_PASSWORD")
	baseURL := os.Getenv("API_BASE_URL")
	mpCode := os.Getenv("MP_CODE")
	return core.UpdateRSS(apiUser, apiPass, baseURL, mpCode)
}

// RunSendOnce triggers the main one-run: monitor/update-if-needed and send
func (a *API) RunSendOnce() error {
	a.mu.Lock()
	a.state.LastAttemptAt = time.Now()
	a.state.LastError = ""
	a.mu.Unlock()

	err := core.SendMailWithArticle(
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
		core.Monitor(),
	)

	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.state.LastError = err.Error()
		return err
	}
	a.state.LastSuccessAt = time.Now()
	return nil
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
