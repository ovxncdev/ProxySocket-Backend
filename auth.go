// auth.go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

// Session store
var (
	sessions   = make(map[string]*Session)
	sessionsMu sync.RWMutex
)

type Session struct {
	Email   string
	Cookies []*http.Cookie
	Client  *http.Client
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	SessionToken string `json:"session_token"`
	Message      string `json:"message"`
}

type LogoutRequest struct {
	SessionToken string `json:"session_token"`
}

const nineProxyBase = "https://9proxy.com"

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, 400, "Email and password required")
		return
	}

	session, err := authenticateNineProxy(req.Email, req.Password)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	token := generateToken()

	sessionsMu.Lock()
	sessions[token] = session
	sessionsMu.Unlock()

	writeJSON(w, 200, LoginResponse{
		SessionToken: token,
		Message:      "Login successful",
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}

	sessionsMu.Lock()
	delete(sessions, req.SessionToken)
	sessionsMu.Unlock()

	writeJSON(w, 200, map[string]string{"message": "Logged out"})
}

func getSession(r *http.Request) (*Session, error) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")

	sessionsMu.RLock()
	session, ok := sessions[token]
	sessionsMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("invalid or expired session")
	}
	return session, nil
}

func authenticateNineProxy(email, password string) (*Session, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	// Step 1: Get login page for CSRF/cookies
	loginURL := nineProxyBase + "/sign-in"
	resp, err := client.Get(loginURL)
	if err != nil {
		return nil, fmt.Errorf("failed to reach 9Proxy: %w", err)
	}
	resp.Body.Close()

	// Step 2: Try form-based login
	formData := url.Values{
		"email":    {email},
		"password": {password},
	}

	req, _ := http.NewRequest("POST", loginURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req.Header.Set("Referer", loginURL)
	req.Header.Set("Origin", nineProxyBase)

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check if we got session cookies
	parsed, _ := url.Parse(nineProxyBase)
	cookies := jar.Cookies(parsed)

	if len(cookies) >= 1 {
		return &Session{
			Email:   email,
			Cookies: cookies,
			Client:  client,
		}, nil
	}

	// Step 3: Try JSON API login as fallback
	jsonBody := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	req, _ = http.NewRequest("POST", nineProxyBase+"/api/auth/login", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JSON login failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("login failed (status %d): %s", resp.StatusCode, string(body))
	}

	cookies = jar.Cookies(parsed)

	return &Session{
		Email:   email,
		Cookies: cookies,
		Client:  client,
	}, nil
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
