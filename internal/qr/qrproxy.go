package qr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type proxy struct {
	prefix          string
	baseURLProvider func() string
	client          *http.Client
	tokenMu         sync.RWMutex
	cachedToken     string
	cachedTokenAt   time.Time
	cachedCookies   []string
}

// NewProxy creates an http.Handler that proxies GET requests from
//
//	<prefix>...  ==>  <API_BASE_URL>/api/v1/wx/auth/qr/...
//
// The base URL is provided dynamically via baseURLProvider to allow env reloads.
func NewProxy(prefix string, baseURLProvider func() string) http.Handler {
	return &proxy{
		prefix:          strings.TrimSuffix(prefix, "/") + "/",
		baseURLProvider: baseURLProvider,
		client:          &http.Client{Timeout: 15 * time.Second},
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	base := strings.TrimRight(p.baseURLProvider(), "/")
	if base == "" {
		writeJSONError(w, http.StatusBadRequest, "API_BASE_URL not configured")
		return
	}
	// 获取/缓存 Bearer Token
	token, err := p.getAccessToken()
	if err != nil || strings.TrimSpace(token) == "" {
		writeJSONError(w, http.StatusUnauthorized, fmt.Sprintf("auth failed: %v", err))
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, p.prefix)
	var upstream string
	if strings.HasPrefix(tail, "static/") {
		// 静态二维码图片：直接映射到根静态路径
		upstream = base + "/" + tail
	} else {
		upstream = base + "/api/v1/wx/auth/qr/" + tail
	}

	u, err := neturl.Parse(upstream)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid upstream url")
		return
	}
	q := u.Query()
	for k, vs := range r.URL.Query() {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	// 可选：将 token 注入查询参数
	if qp := strings.TrimSpace(os.Getenv("QR_TOKEN_QUERY")); qp != "" {
		q.Set(qp, token)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "build upstream request failed")
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	} else {
		req.Header.Set("Accept", "*/*")
	}
	// 使用登录获取的 Token 注入到自定义 Header（默认 Authorization: Bearer ...）
	hdr := os.Getenv("QR_TOKEN_HEADER")
	if hdr == "" {
		hdr = "Authorization"
	}
	prefix := os.Getenv("QR_TOKEN_PREFIX")
	if prefix == "" {
		prefix = "Bearer "
	}
	req.Header.Set(hdr, prefix+token)
	// 可选：将 token 注入 cookie
	var cookieParts []string
	if cn := strings.TrimSpace(os.Getenv("QR_TOKEN_COOKIE")); cn != "" {
		cookieParts = append(cookieParts, cn+"="+token)
	}
	// 合并缓存的登录 Cookie 与来访 Cookie
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		cookieParts = append(cookieParts, cookie)
	}
	p.tokenMu.RLock()
	if len(p.cachedCookies) > 0 {
		cookieParts = append(cookieParts, p.cachedCookies...)
	}
	p.tokenMu.RUnlock()
	if len(cookieParts) > 0 {
		req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	// 若鉴权失败，强制刷新 token+cookie 重试一次
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		p.invalidateToken()
		if token, err = p.getAccessToken(); err == nil && token != "" {
			req2, _ := http.NewRequest(http.MethodGet, u.String(), nil)
			if accept := r.Header.Get("Accept"); accept != "" {
				req2.Header.Set("Accept", accept)
			} else {
				req2.Header.Set("Accept", "*/*")
			}
			hdr := os.Getenv("QR_TOKEN_HEADER")
			if hdr == "" {
				hdr = "Authorization"
			}
			prefix := os.Getenv("QR_TOKEN_PREFIX")
			if prefix == "" {
				prefix = "Bearer "
			}
			req2.Header.Set(hdr, prefix+token)
			var cookieParts2 []string
			if cn := strings.TrimSpace(os.Getenv("QR_TOKEN_COOKIE")); cn != "" {
				cookieParts2 = append(cookieParts2, cn+"="+token)
			}
			if cookie := r.Header.Get("Cookie"); cookie != "" {
				cookieParts2 = append(cookieParts2, cookie)
			}
			p.tokenMu.RLock()
			if len(p.cachedCookies) > 0 {
				cookieParts2 = append(cookieParts2, p.cachedCookies...)
			}
			p.tokenMu.RUnlock()
			if len(cookieParts2) > 0 {
				req2.Header.Set("Cookie", strings.Join(cookieParts2, "; "))
			}
			resp, err = p.client.Do(req2)
			if err != nil {
				writeJSONError(w, http.StatusBadGateway, err.Error())
				return
			}
		}
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "set-cookie" || strings.HasPrefix(lk, "cache-") || lk == "expires" || lk == "last-modified" || lk == "pragma" || lk == "content-disposition" || lk == "content-length" {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+escapeForJSON(msg)+`"}`)
}

func escapeForJSON(s string) string {
	// minimal escaping sufficient for simple error messages
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, `"`, `\\"`)
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// getAccessToken 登录获取 access token，并做简单缓存
func (p *proxy) getAccessToken() (string, error) {
	// 10 分钟简单缓存
	p.tokenMu.RLock()
	if p.cachedToken != "" && time.Since(p.cachedTokenAt) < 10*time.Minute {
		tok := p.cachedToken
		p.tokenMu.RUnlock()
		return tok, nil
	}
	p.tokenMu.RUnlock()

	username := strings.TrimSpace(os.Getenv("API_USERNAME"))
	password := strings.TrimSpace(os.Getenv("API_PASSWORD"))
	base := strings.TrimRight(p.baseURLProvider(), "/")
	if username == "" || password == "" || base == "" {
		return "", fmt.Errorf("missing credentials or base url")
	}

	loginURL := base + "/api/v1/wx/auth/login"
	form := neturl.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "")
	form.Set("client_id", "string")
	form.Set("client_secret", "string")

	req, err := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login status %d: %s", resp.StatusCode, string(b))
	}

	var auth struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return "", err
	}
	if auth.Code != 0 || strings.TrimSpace(auth.Data.AccessToken) == "" {
		return "", fmt.Errorf("login failed: code=%d msg=%s", auth.Code, auth.Message)
	}

	// 记录 token 与登录 Cookie
	p.tokenMu.Lock()
	p.cachedToken = auth.Data.AccessToken
	p.cachedTokenAt = time.Now()
	if setCookies := resp.Header.Values("Set-Cookie"); len(setCookies) > 0 {
		p.cachedCookies = setCookies
	}
	p.tokenMu.Unlock()
	return auth.Data.AccessToken, nil
}

func (p *proxy) invalidateToken() {
	p.tokenMu.Lock()
	p.cachedToken = ""
	p.cachedCookies = nil
	p.cachedTokenAt = time.Time{}
	p.tokenMu.Unlock()
}

// DoAuthenticatedGET performs a GET to the upstream QR auth path using the same
// login/token/cookie strategy as the proxy, and returns status code and body.
// localPath should be one of:
//   - "/api/wx/auth/qr/..."
//   - "/api/v1/wx/auth/qr/..."
//   - or "static/..." (relative path under upstream base for static files)
func DoAuthenticatedGET(localPath string, baseURLProvider func() string) (int, []byte, error) {
	p := &proxy{
		prefix:          "",
		baseURLProvider: baseURLProvider,
		client:          &http.Client{Timeout: 15 * time.Second},
	}

	base := strings.TrimRight(baseURLProvider(), "/")
	if base == "" {
		return 0, nil, fmt.Errorf("API_BASE_URL not configured")
	}

	token, err := p.getAccessToken()
	if err != nil || strings.TrimSpace(token) == "" {
		return 0, nil, fmt.Errorf("auth failed: %v", err)
	}

	// Map local path to upstream URL
	var upstream string
	if strings.HasPrefix(localPath, "/api/v1/wx/auth/qr/") {
		upstream = base + localPath
	} else if strings.HasPrefix(localPath, "/api/wx/auth/qr/") {
		tail := strings.TrimPrefix(localPath, "/api/wx/auth/qr/")
		if strings.HasPrefix(tail, "static/") {
			upstream = base + "/" + tail
		} else {
			upstream = base + "/api/v1/wx/auth/qr/" + tail
		}
	} else if strings.HasPrefix(localPath, "static/") {
		upstream = base + "/" + localPath
	} else {
		// fallback: pass through as-is (absolute or relative)
		if strings.HasPrefix(localPath, "http://") || strings.HasPrefix(localPath, "https://") {
			upstream = localPath
		} else {
			upstream = base + "/" + strings.TrimLeft(localPath, "/")
		}
	}

	u, err := neturl.Parse(upstream)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid upstream url")
	}

	// Optional query token injection
	if qp := strings.TrimSpace(os.Getenv("QR_TOKEN_QUERY")); qp != "" {
		q := u.Query()
		q.Set(qp, token)
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	if accept := "*/*"; accept != "" {
		req.Header.Set("Accept", accept)
	}
	// Header token
	hdr := os.Getenv("QR_TOKEN_HEADER")
	if hdr == "" {
		hdr = "Authorization"
	}
	prefix := os.Getenv("QR_TOKEN_PREFIX")
	if prefix == "" {
		prefix = "Bearer "
	}
	req.Header.Set(hdr, prefix+token)

	// Cookie token and cached cookies
	var cookieParts []string
	if cn := strings.TrimSpace(os.Getenv("QR_TOKEN_COOKIE")); cn != "" {
		cookieParts = append(cookieParts, cn+"="+token)
	}
	if len(p.cachedCookies) > 0 {
		cookieParts = append(cookieParts, p.cachedCookies...)
	}
	if len(cookieParts) > 0 {
		req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}
