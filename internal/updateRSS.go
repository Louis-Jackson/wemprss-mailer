package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type authResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		AccessToken string `json:"access_token"`
	} `json:"data"`
}

// UpdateRSS 更新最新的 wechat 文章：先获取访问 token，再调用更新接口
func UpdateRSS(APIUsername, APIPassword, loginURL, mpCode string) bool {
	client := &http.Client{Timeout: 15 * time.Second}

	// 1) 获取访问 token（表单 x-www-form-urlencoded）
	loginEndpoint := fmt.Sprintf("%s/api/v1/wx/auth/login", strings.TrimRight(loginURL, "/"))
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", APIUsername)
	form.Set("password", APIPassword)
	form.Set("scope", "")
	form.Set("client_id", "string")
	form.Set("client_secret", "string")

	req, err := http.NewRequest(http.MethodPost, loginEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		log.Println("构造登录请求失败:", err)
		return false
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	log.Println("正在获取API访问token...")
	resp, err := client.Do(req)
	if err != nil {
		log.Println("请求登录接口失败:", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("登录接口返回非 2xx: %d, body: %s\n", resp.StatusCode, string(b))
		return false
	}

	var auth authResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		log.Println("解析登录响应失败:", err)
		return false
	}
	if auth.Code != 0 {
		log.Printf("获取token失败，返回码: %d, 消息: %s\n", auth.Code, auth.Message)
		return false
	}
	accessToken := auth.Data.AccessToken
	if accessToken == "" {
		log.Println("无法从响应数据中获取access token")
		return false
	}
	log.Println("成功获取access token")

	// 2) 调用更新接口（GET，带查询参数和 Bearer Token）
	refreshEndpoint := fmt.Sprintf("%s/api/v1/wx/mps/update/%s", strings.TrimRight(loginURL, "/"), mpCode)
	q := url.Values{}
	q.Set("start_page", "0")
	q.Set("end_page", "1")

	refreshReq, err := http.NewRequest(http.MethodGet, refreshEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		log.Println("构造更新请求失败:", err)
		return false
	}
	refreshReq.Header.Set("accept", "application/json")
	refreshReq.Header.Set("Authorization", "Bearer "+accessToken)

	log.Println("正在更新微信文章...")
	refreshResp, err := client.Do(refreshReq)
	if err != nil {
		log.Println("更新请求失败:", err)
		return false
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode < 200 || refreshResp.StatusCode >= 300 {
		b, _ := io.ReadAll(refreshResp.Body)
		log.Printf("更新接口返回非 2xx: %d, body: %s\n", refreshResp.StatusCode, string(b))
		return false
	}

	log.Println("微信文章更新成功")
	time.Sleep(time.Second * 10)
	return true
}
