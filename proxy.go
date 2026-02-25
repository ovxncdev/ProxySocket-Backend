// proxy.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type ProxyItem struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Protocol    string `json:"protocol_type"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	IP          string `json:"ip"`
	IsOnline    bool   `json:"is_online"`
}

type ProxyListResponse struct {
	Proxies []ProxyItem `json:"proxies"`
	Total   int         `json:"total"`
}

type ForwardRequest struct {
	ProxyID string `json:"proxy_id"`
	Port    int    `json:"port"`
}

type ForwardResponse struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Protocol string `json:"protocol_type"`
	Message  string `json:"message"`
}

type PortStatusItem struct {
	Address  string `json:"address"`
	City     string `json:"city"`
	PublicIP string `json:"public_ip"`
	Online   bool   `json:"online"`
}

// 9Proxy API response structure
type nineProxyResponse struct {
	Error   bool            `json:"error"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type nineProxyTodayItem struct {
	ID          string `json:"id"`
	City        string `json:"city"`
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	IsOnline    bool   `json:"is_online"`
	Binding     any    `json:"binding"`
}

type nineProxyPortItem struct {
	Address  string `json:"address"`
	City     string `json:"city"`
	PublicIP string `json:"public_ip"`
	Online   bool   `json:"online"`
}

func handleTodayList(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	// Build query params from request
	query := r.URL.Query()
	params := "?t=2"
	if v := query.Get("country"); v != "" {
		params += "&country=" + v
	}
	if v := query.Get("city"); v != "" {
		params += "&city=" + v
	}
	if v := query.Get("isp"); v != "" {
		params += "&isp=" + v
	}
	if v := query.Get("limit"); v != "" {
		params += "&limit=" + v
	} else {
		params += "&limit=50"
	}

	// Call 9Proxy API
	apiURL := nineProxyBase + "/api/today_list" + params
	body, err := doNineProxyRequest(session, apiURL)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	var resp nineProxyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		writeError(w, 500, "Failed to parse 9Proxy response")
		return
	}

	if resp.Error {
		writeError(w, 500, resp.Message)
		return
	}

	var items []nineProxyTodayItem
	if err := json.Unmarshal(resp.Data, &items); err != nil {
		writeError(w, 500, "Failed to parse proxy list")
		return
	}

	proxies := make([]ProxyItem, 0, len(items))
	for _, item := range items {
		proxies = append(proxies, ProxyItem{
			ID:          item.ID,
			Host:        item.IP,
			IP:          item.IP,
			Protocol:    "SOCKS5",
			CountryCode: item.CountryCode,
			City:        item.City,
			IsOnline:    item.IsOnline,
		})
	}

	writeJSON(w, 200, ProxyListResponse{
		Proxies: proxies,
		Total:   len(proxies),
	})
}

func handleForward(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	var req ForwardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}

	if req.ProxyID == "" || req.Port == 0 {
		writeError(w, 400, "proxy_id and port required")
		return
	}

	apiURL := fmt.Sprintf("%s/api/forward?id=%s&port=%d&t=2",
		nineProxyBase, req.ProxyID, req.Port)

	body, err := doNineProxyRequest(session, apiURL)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	var resp nineProxyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		writeError(w, 500, "Failed to parse 9Proxy response")
		return
	}

	if resp.Error {
		writeError(w, 500, resp.Message)
		return
	}

	writeJSON(w, 200, ForwardResponse{
		Host:     "127.0.0.1",
		Port:     req.Port,
		Protocol: "SOCKS5",
		Message:  resp.Message,
	})
}

func handlePortStatus(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	apiURL := nineProxyBase + "/api/port_status?t=2"
	body, err := doNineProxyRequest(session, apiURL)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	var resp nineProxyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		writeError(w, 500, "Failed to parse 9Proxy response")
		return
	}

	if resp.Error {
		writeError(w, 500, resp.Message)
		return
	}

	var items []nineProxyPortItem
	if err := json.Unmarshal(resp.Data, &items); err != nil {
		writeError(w, 500, "Failed to parse port status")
		return
	}

	ports := make([]PortStatusItem, 0, len(items))
	for _, item := range items {
		ports = append(ports, PortStatusItem{
			Address:  item.Address,
			City:     item.City,
			PublicIP: item.PublicIP,
			Online:   item.Online,
		})
	}

	writeJSON(w, 200, ports)
}

func doNineProxyRequest(session *Session, url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req.Header.Set("Referer", nineProxyBase+"/dashboard")

	// Add session cookies
	for _, cookie := range session.Cookies {
		req.AddCookie(cookie)
	}

	resp, err := session.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("9Proxy request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("9Proxy returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
