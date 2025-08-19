package qr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path"
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
	// 对疑似二维码/图片资源增加 2s 延时，缓解上游生成/刷新未就绪的问题
	if shouldDelayForPath(tail) {
		time.Sleep(2 * time.Second)
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

	// 针对 static/ 二维码图片，若 404 则短暂重试几次（上游可能尚未生成完毕）
	if strings.HasPrefix(tail, "static/") && (resp.StatusCode == http.StatusNotFound) {
		maxRetry := 3
		interval := 700 * time.Millisecond
		for i := 0; i < maxRetry && resp.StatusCode == http.StatusNotFound; i++ {
			resp.Body.Close()
			time.Sleep(interval)
			reqR, _ := http.NewRequest(http.MethodGet, u.String(), nil)
			if accept := r.Header.Get("Accept"); accept != "" {
				reqR.Header.Set("Accept", accept)
			} else {
				reqR.Header.Set("Accept", "*/*")
			}
			hdr := os.Getenv("QR_TOKEN_HEADER")
			if hdr == "" {
				hdr = "Authorization"
			}
			prefix := os.Getenv("QR_TOKEN_PREFIX")
			if prefix == "" {
				prefix = "Bearer "
			}
			reqR.Header.Set(hdr, prefix+token)
			var cookiePartsR []string
			if cn := strings.TrimSpace(os.Getenv("QR_TOKEN_COOKIE")); cn != "" {
				cookiePartsR = append(cookiePartsR, cn+"="+token)
			}
			if cookie := r.Header.Get("Cookie"); cookie != "" {
				cookiePartsR = append(cookiePartsR, cookie)
			}
			p.tokenMu.RLock()
			if len(p.cachedCookies) > 0 {
				cookiePartsR = append(cookiePartsR, p.cachedCookies...)
			}
			p.tokenMu.RUnlock()
			if len(cookiePartsR) > 0 {
				reqR.Header.Set("Cookie", strings.Join(cookiePartsR, "; "))
			}
			resp, err = p.client.Do(reqR)
			if err != nil {
				writeJSONError(w, http.StatusBadGateway, err.Error())
				return
			}
		}
	}

	defer resp.Body.Close()

	// 若为二维码/图片资源，先保存到本地临时文件，再映射返回给客户端，最后自动删除
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if shouldPersistQRCode(tail, ct) && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// 生成带后缀的临时文件名
		ext := guessImageExt(ct, u.Path)
		pattern := "qrimg-*" + ext
		f, ferr := os.CreateTemp(os.TempDir(), pattern)
		if ferr == nil {
			// 保存响应体到文件
			_, _ = io.Copy(f, resp.Body)
			_ = f.Close()
			// 重新打开文件并回传
			rf, rerr := os.Open(f.Name())
			if rerr == nil {
				defer rf.Close()
				defer os.Remove(f.Name())
				// 透传必要的头（与下方逻辑一致）
				for k, vs := range resp.Header {
					lk := strings.ToLower(k)
					if lk == "content-type" || lk == "set-cookie" || strings.HasPrefix(lk, "cache-") || lk == "expires" || lk == "last-modified" || lk == "pragma" || lk == "content-disposition" || lk == "content-length" {
						for _, v := range vs {
							w.Header().Add(k, v)
						}
					}
				}
				// 显式设置 content-type（以防上游未返回）
				if ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				// 禁止缓存，避免浏览器/中间层缓存旧二维码
				w.Header().Set("Cache-Control", "no-store, max-age=0, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Del("Expires")
				// 返回状态码与文件内容
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, rf)
				return
			}
			// 若回传失败，清理文件后回退到直传逻辑
			_ = os.Remove(f.Name())
		}
		// 若创建临时文件失败，则回退到直传逻辑
	}

	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "set-cookie" || strings.HasPrefix(lk, "cache-") || lk == "expires" || lk == "last-modified" || lk == "pragma" || lk == "content-disposition" || lk == "content-length" {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	}
	// 若为二维码/图片资源，强制不缓存，保证刷新时获取最新
	if shouldPersistQRCode(tail, strings.ToLower(resp.Header.Get("Content-Type"))) {
		w.Header().Set("Cache-Control", "no-store, max-age=0, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Del("Expires")
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

// shouldPersistQRCode 判断是否需要先落盘再返回（针对二维码/图片类资源）
func shouldPersistQRCode(requestTail string, contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "image/") {
		return true
	}
	// 根据路径与扩展名进行兜底判断
	lowerPath := strings.ToLower(requestTail)
	ext := strings.ToLower(path.Ext(lowerPath))
	if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".bmp" || ext == ".webp" || ext == ".svg" {
		return true
	}
	// 一些接口路径中可能包含 qr 或 qrcode 关键词
	if strings.Contains(lowerPath, "/qr") || strings.Contains(lowerPath, "qrcode") {
		return true
	}
	return false
}

// guessImageExt 根据 Content-Type 或 URL 路径猜测合适的图片扩展名
func guessImageExt(contentType string, urlPath string) string {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch ct {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/jpg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "image/bmp":
		return ".bmp"
	case "image/svg+xml":
		return ".svg"
	}
	// 兜底：从路径扩展名推断
	if ext := strings.ToLower(path.Ext(urlPath)); ext != "" {
		return ext
	}
	return ".img"
}

// shouldDelayForPath 判断是否需要对上游请求增加小延时（主要针对二维码/图片生成尚未就绪的场景）
func shouldDelayForPath(requestTail string) bool {
	lower := strings.ToLower(requestTail)
	// 明确包含 qr/qrcode 的路径
	if strings.Contains(lower, "/qr") || strings.Contains(lower, "qrcode") {
		return true
	}
	// 静态目录下的图片资源也可能是二维码
	if strings.HasPrefix(lower, "static/") {
		ext := strings.ToLower(path.Ext(lower))
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".bmp" || ext == ".webp" || ext == ".svg" {
			return true
		}
	}
	return false
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
