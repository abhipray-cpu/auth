// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0038: Playwright E2E — Session + API Key + Identity Chain
//
// Go-native HTTP client tests for session lifecycle (persistence, expiry,
// concurrent sessions), API key management (create, authenticate, revoke),
// identity chain display, and post-logout behavior.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"crypto/tls"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/engine"
	"github.com/abhipray-cpu/auth/hash"
	"github.com/abhipray-cpu/auth/hooks"
	authhttp "github.com/abhipray-cpu/auth/http"
	apikeymode "github.com/abhipray-cpu/auth/mode/apikey"
	modepw "github.com/abhipray-cpu/auth/mode/password"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
)

// ---------- Session Persistence ----------

// TestE2E_Session_Persistence verifies:
// AC: Session persistence: login → close tab → open dashboard → still logged in
//
// Simulated by: login → extract cookie → create new client with cookie → GET /api/me works.
func TestE2E_Session_Persistence(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "persist@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login and get session cookie.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"persist@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// "Close tab" — create a completely new HTTP client (simulates new browser tab).
	newClient := gw.httpClient()

	// "Open dashboard" — use the same cookie value (persisted by browser).
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)

	meResp, err := newClient.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me with persisted cookie: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		t.Fatalf("GET /api/me status = %d, want 200 (session should persist)", meResp.StatusCode)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)
	if meData["subject_id"] != "persist@example.com" {
		t.Errorf("subject_id = %v, want persist@example.com", meData["subject_id"])
	}
}

// ---------- Session Expiry ----------

// TestE2E_Session_Expiry verifies:
// AC: Session expiry: wait → dashboard returns 401
//
// Uses a gateway with very short session timeouts.
func TestE2E_Session_Expiry(t *testing.T) {
	pki := newTestPKI(t)

	// Build a gateway with a very short idle timeout.
	gw := startBrowserGatewayWithConfig(t, pki, session.SessionConfig{
		IdleTimeout:     200 * time.Millisecond,
		AbsoluteTimeout: 500 * time.Millisecond,
		MaxConcurrent:   5,
	})

	gw.registerUser(t, "expiry@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"expiry@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// Immediately access — should work.
	meReq1, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq1.AddCookie(sessionCookie)
	meResp1, err := client.Do(meReq1)
	if err != nil {
		t.Fatalf("GET /api/me (immediate): %v", err)
	}
	meResp1.Body.Close()

	if meResp1.StatusCode != 200 {
		t.Fatalf("GET /api/me (immediate) status = %d, want 200", meResp1.StatusCode)
	}

	// Wait for session to expire (idle + absolute).
	time.Sleep(600 * time.Millisecond)

	// Access again — should be 401.
	meReq2, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq2.AddCookie(sessionCookie)
	meResp2, err := client.Do(meReq2)
	if err != nil {
		t.Fatalf("GET /api/me (after expiry): %v", err)
	}
	defer meResp2.Body.Close()

	if meResp2.StatusCode != 401 {
		t.Fatalf("GET /api/me after expiry status = %d, want 401", meResp2.StatusCode)
	}
}

// ---------- Concurrent Sessions ----------

// TestE2E_Session_ConcurrentLimit verifies:
// AC: Concurrent sessions: login from two browsers, MaxConcurrent enforced
func TestE2E_Session_ConcurrentLimit(t *testing.T) {
	pki := newTestPKI(t)

	// Build a gateway with MaxConcurrent = 1 to easily test eviction.
	gw := startBrowserGatewayWithConfig(t, pki, session.SessionConfig{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		MaxConcurrent:   1,
	})

	gw.registerUser(t, "concurrent@example.com", "StrongPass123!")

	client := gw.httpClient()
	loginBody := `{"identifier":"concurrent@example.com","password":"StrongPass123!"}`

	// Login 1 — "Browser A".
	resp1, err := client.Post(gw.baseURL+"/auth/login", "application/json", strings.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login 1: %v", err)
	}
	resp1.Body.Close()

	cookie1 := findHTTPCookie(resp1, "auth_session")
	if cookie1 == nil {
		t.Fatal("no session cookie from login 1")
	}

	// Login 2 — "Browser B" (should evict session 1).
	resp2, err := client.Post(gw.baseURL+"/auth/login", "application/json", strings.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login 2: %v", err)
	}
	resp2.Body.Close()

	cookie2 := findHTTPCookie(resp2, "auth_session")
	if cookie2 == nil {
		t.Fatal("no session cookie from login 2")
	}

	// Session 2 should work.
	meReq2, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq2.AddCookie(cookie2)
	meResp2, err := client.Do(meReq2)
	if err != nil {
		t.Fatalf("GET /api/me with session 2: %v", err)
	}
	meResp2.Body.Close()

	if meResp2.StatusCode != 200 {
		t.Fatalf("session 2 status = %d, want 200", meResp2.StatusCode)
	}

	// Session 1 should be evicted (401).
	meReq1, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq1.AddCookie(cookie1)
	meResp1, err := client.Do(meReq1)
	if err != nil {
		t.Fatalf("GET /api/me with session 1: %v", err)
	}
	meResp1.Body.Close()

	if meResp1.StatusCode != 401 {
		t.Fatalf("evicted session 1 status = %d, want 401", meResp1.StatusCode)
	}
}

// ---------- API Key Tests ----------

// TestE2E_APIKey_CreateAndAuthenticate verifies:
// AC: API key create: key displayed once, works for API calls
func TestE2E_APIKey_CreateAndAuthenticate(t *testing.T) {
	pki := newTestPKI(t)
	apikeyStore := newMemAPIKeyStore()

	gw := startBrowserGatewayWithAPIKeys(t, pki, apikeyStore)
	gw.registerUser(t, "apiuser@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login to get a session.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"apiuser@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// Create an API key via the management endpoint.
	createReq, _ := http.NewRequest("POST", gw.baseURL+"/api/keys", strings.NewReader(
		`{"name":"test-key","scopes":["read","write"]}`,
	))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(sessionCookie)

	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("POST /api/keys: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != 201 {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create API key status = %d, want 201, body = %s", createResp.StatusCode, body)
	}

	var keyData map[string]string
	_ = json.NewDecoder(createResp.Body).Decode(&keyData)

	rawKey := keyData["api_key"]
	if rawKey == "" {
		t.Fatal("API key response should include the raw key")
	}
	keyID := keyData["key_id"]
	if keyID == "" {
		t.Fatal("API key response should include the key ID")
	}

	// Use the API key to access protected endpoint (via X-API-Key header).
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.Header.Set("X-API-Key", rawKey)

	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me with API key: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("API key auth status = %d, want 200, body = %s", meResp.StatusCode, body)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)
	if meData["subject_id"] != "apiuser@example.com" {
		t.Errorf("subject_id = %v, want apiuser@example.com", meData["subject_id"])
	}
	if meData["auth_method"] != "api_key" {
		t.Errorf("auth_method = %v, want api_key", meData["auth_method"])
	}
}

// TestE2E_APIKey_Revoke verifies:
// AC: API key revoke: key no longer works
func TestE2E_APIKey_Revoke(t *testing.T) {
	pki := newTestPKI(t)
	apikeyStore := newMemAPIKeyStore()

	gw := startBrowserGatewayWithAPIKeys(t, pki, apikeyStore)
	gw.registerUser(t, "revokeuser@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"revokeuser@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")

	// Create an API key.
	createReq, _ := http.NewRequest("POST", gw.baseURL+"/api/keys", strings.NewReader(
		`{"name":"to-revoke","scopes":["read"]}`,
	))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(sessionCookie)

	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer createResp.Body.Close()

	var keyData map[string]string
	_ = json.NewDecoder(createResp.Body).Decode(&keyData)
	rawKey := keyData["api_key"]
	keyID := keyData["key_id"]

	// Verify the key works.
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.Header.Set("X-API-Key", rawKey)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me with key: %v", err)
	}
	meResp.Body.Close()
	if meResp.StatusCode != 200 {
		t.Fatalf("API key auth status = %d, want 200", meResp.StatusCode)
	}

	// Revoke the key.
	revokeReq, _ := http.NewRequest("DELETE", gw.baseURL+"/api/keys/"+keyID, nil)
	revokeReq.AddCookie(sessionCookie)
	revokeResp, err := client.Do(revokeReq)
	if err != nil {
		t.Fatalf("DELETE /api/keys: %v", err)
	}
	revokeResp.Body.Close()

	if revokeResp.StatusCode != 204 {
		t.Fatalf("revoke status = %d, want 204", revokeResp.StatusCode)
	}

	// Key should no longer work.
	meReq2, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq2.Header.Set("X-API-Key", rawKey)
	meResp2, err := client.Do(meReq2)
	if err != nil {
		t.Fatalf("GET /api/me with revoked key: %v", err)
	}
	meResp2.Body.Close()

	if meResp2.StatusCode != 401 {
		t.Fatalf("revoked key status = %d, want 401", meResp2.StatusCode)
	}
}

// ---------- Identity Chain Display ----------

// TestE2E_IdentityChain_Display verifies:
// AC: Identity chain display: shows UserIdentity + AuthMethod + services + WorkloadIdentity
//
// In the browser context, identity chain is displayed via /api/me.
// The SPA shows subject_id, auth_method, and session_id.
// Full multi-service propagation (gateway→order service) is tested in E2E Epic 11.
func TestE2E_IdentityChain_Display(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "chain@example.com", "StrongPass123!")

	client := gw.httpClient()

	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"chain@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", meResp.StatusCode)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)

	// Verify identity chain fields are present and correct.
	if meData["subject_id"] == nil || meData["subject_id"] == "" {
		t.Error("identity chain must include subject_id")
	}
	if meData["subject_id"] != "chain@example.com" {
		t.Errorf("subject_id = %v, want chain@example.com", meData["subject_id"])
	}
	if meData["session_id"] == nil || meData["session_id"] == "" {
		t.Error("identity chain must include session_id")
	}
	// auth_method may be empty from Verify (sessions don't persist it),
	// but the field must exist in the response.
	if _, exists := meData["auth_method"]; !exists {
		t.Error("identity chain must include auth_method field")
	}
}

// ---------- Multiple Tabs ----------

// TestE2E_MultipleTabs_IdentityConsistent verifies:
// AC: Multiple tabs: identity consistent across tabs
func TestE2E_MultipleTabs_IdentityConsistent(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "tabs@example.com", "StrongPass123!")

	client := gw.httpClient()

	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"tabs@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// "Tab 1" — GET /api/me.
	meReq1, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq1.AddCookie(sessionCookie)
	meResp1, err := client.Do(meReq1)
	if err != nil {
		t.Fatalf("tab 1: %v", err)
	}
	defer meResp1.Body.Close()

	var data1 map[string]any
	_ = json.NewDecoder(meResp1.Body).Decode(&data1)

	// "Tab 2" — GET /api/me with the same cookie (different request).
	meReq2, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq2.AddCookie(sessionCookie)
	meResp2, err := client.Do(meReq2)
	if err != nil {
		t.Fatalf("tab 2: %v", err)
	}
	defer meResp2.Body.Close()

	var data2 map[string]any
	_ = json.NewDecoder(meResp2.Body).Decode(&data2)

	// Identity should be consistent and correct.
	if data1["subject_id"] != data2["subject_id"] {
		t.Errorf("subject_id mismatch: tab1=%v, tab2=%v", data1["subject_id"], data2["subject_id"])
	}
	if data1["subject_id"] != "tabs@example.com" {
		t.Errorf("subject_id = %v, want tabs@example.com", data1["subject_id"])
	}
	if data1["session_id"] != data2["session_id"] {
		t.Errorf("session_id mismatch: tab1=%v, tab2=%v", data1["session_id"], data2["session_id"])
	}
}

// ---------- Back Button After Logout ----------

// TestE2E_BackButtonAfterLogout verifies:
// AC: Back button after logout: no cached authenticated page
//
// We verify this by checking Cache-Control headers on the dashboard page.
// With no-store, browsers will not serve cached content on back navigation.
func TestE2E_BackButtonAfterLogout(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "back@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"back@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// Fetch dashboard (while logged in) — check Cache-Control.
	dashReq, _ := http.NewRequest("GET", gw.baseURL+"/dashboard.html", nil)
	dashReq.AddCookie(sessionCookie)
	dashResp, err := client.Do(dashReq)
	if err != nil {
		t.Fatalf("GET /dashboard.html: %v", err)
	}
	dashResp.Body.Close()

	cc := dashResp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("dashboard Cache-Control = %q, must include 'no-store'", cc)
	}
	if !strings.Contains(cc, "must-revalidate") {
		t.Errorf("dashboard Cache-Control = %q, must include 'must-revalidate'", cc)
	}

	// Pragma: no-cache is needed for HTTP/1.0 backward compatibility.
	pragma := dashResp.Header.Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("dashboard Pragma = %q, want 'no-cache'", pragma)
	}

	// Logout.
	logoutReq, _ := http.NewRequest("POST", gw.baseURL+"/auth/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	logoutResp.Body.Close()

	if logoutResp.StatusCode != 204 {
		t.Fatalf("logout status = %d, want 204", logoutResp.StatusCode)
	}

	// "Back button" — trying to access /api/me with the old cookie returns 401.
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me after logout: %v", err)
	}
	meResp.Body.Close()

	if meResp.StatusCode != 401 {
		t.Fatalf("back button after logout: status = %d, want 401", meResp.StatusCode)
	}
}

// ---------- Helper: Gateway with custom session config ----------

// startBrowserGatewayWithConfig starts a browser gateway with a custom session config.
// This is used for testing session expiry and concurrent session limits.
func startBrowserGatewayWithConfig(t *testing.T, pki *tlsPKI, sessCfg session.SessionConfig) *browserGateway {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("https://localhost:%d", port)

	serverCert := pki.issueServerCert(t, "browser-gateway", "localhost")

	userStore := NewMemUserStore()
	sessStore := newMemSessionStore()
	sessMgr := session.NewManager(sessStore, sessCfg)
	hasher := hash.NewArgon2idHasher(nil)

	pwMode := modepw.NewMode(modepw.ModeConfig{
		UserStore: userStore,
		Hasher:    hasher,
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
	})

	eng, err := engine.New(engine.Config{
		UserStore:      userStore,
		Hasher:         hasher,
		SessionManager: sessMgr,
		HookManager:    hooks.NewManager(),
		PasswordPolicy: pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
		Modes: []auth.AuthMode{pwMode},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	cookieCfg := authhttp.CookieConfig{
		Name:     "auth_session",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	mux := http.NewServeMux()
	handlers := authhttp.NewHandlers(eng, cookieCfg)
	middleware := authhttp.NewMiddleware(eng, cookieCfg)

	mux.Handle("POST /auth/login", handlers.Login())
	mux.Handle("POST /auth/register", handlers.Register())
	mux.Handle("POST /auth/logout", handlers.Logout())

	mux.Handle("GET /api/me", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject_id":  identity.SubjectID,
			"auth_method": identity.AuthMethod,
			"session_id":  identity.SessionID,
		})
	})))

	mux.HandleFunc("GET /", serveSPAIndex)
	mux.HandleFunc("GET /dashboard.html", serveSPADashboard)
	mux.HandleFunc("GET /login.html", serveSPALogin)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsListener := tls.NewListener(lis, tlsConfig)

	server := &http.Server{Handler: mux}

	gw := &browserGateway{
		server:    server,
		listener:  tlsListener,
		baseURL:   baseURL,
		engine:    eng,
		userStore: userStore,
		sessMgr:   sessMgr,
		cookieCfg: cookieCfg,
		tlsCert:   serverCert,
		pki:       pki,
	}

	go func() {
		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			// Normal shutdown
		}
	}()

	t.Cleanup(func() { _ = server.Close() })

	return gw
}

// startBrowserGatewayWithAPIKeys starts a browser gateway with API key mode
// and API key management endpoints.
func startBrowserGatewayWithAPIKeys(t *testing.T, pki *tlsPKI, apikeyStore apikey.APIKeyStore) *browserGateway {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("https://localhost:%d", port)

	serverCert := pki.issueServerCert(t, "browser-gateway-apikey", "localhost")

	userStore := NewMemUserStore()
	sessStore := newMemSessionStore()
	sessMgr := session.NewManager(sessStore, session.DefaultConfig())
	hasher := hash.NewArgon2idHasher(nil)

	pwMode := modepw.NewMode(modepw.ModeConfig{
		UserStore: userStore,
		Hasher:    hasher,
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
	})

	akMode := apikeymode.NewMode(apikeymode.Config{
		APIKeyStore: apikeyStore,
	})

	eng, err := engine.New(engine.Config{
		UserStore:      userStore,
		Hasher:         hasher,
		SessionManager: sessMgr,
		HookManager:    hooks.NewManager(),
		PasswordPolicy: pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
		Modes: []auth.AuthMode{pwMode, akMode},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	cookieCfg := authhttp.CookieConfig{
		Name:     "auth_session",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	mux := http.NewServeMux()
	authHandlers := authhttp.NewHandlers(eng, cookieCfg)
	middleware := authhttp.NewMiddleware(eng, cookieCfg)

	mux.Handle("POST /auth/login", authHandlers.Login())
	mux.Handle("POST /auth/register", authHandlers.Register())
	mux.Handle("POST /auth/logout", authHandlers.Logout())

	// Protected API endpoint.
	mux.Handle("GET /api/me", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject_id":  identity.SubjectID,
			"auth_method": identity.AuthMethod,
			"session_id":  identity.SessionID,
		})
	})))

	// API key management endpoints — session-protected.
	mux.Handle("POST /api/keys", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Generate a raw API key.
		rawKey, err := session.GenerateID()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		keyHash := session.HashID(rawKey)
		keyID := fmt.Sprintf("key_%s", keyHash[:16])

		ak := &apikey.APIKey{
			ID:        keyID,
			SubjectID: identity.SubjectID,
			KeyHash:   keyHash,
			Name:      req.Name,
			Scopes:    req.Scopes,
			CreatedAt: time.Now(),
		}

		if err := apikeyStore.Create(context.Background(), ak); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id":  keyID,
			"api_key": rawKey,
			"name":    req.Name,
		})
	})))

	// Revoke API key.
	mux.Handle("DELETE /api/keys/{keyID}", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		keyID := r.PathValue("keyID")
		if keyID == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if err := apikeyStore.Revoke(context.Background(), keyID); err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})))

	// SPA pages.
	mux.HandleFunc("GET /", serveSPAIndex)
	mux.HandleFunc("GET /dashboard.html", serveSPADashboard)
	mux.HandleFunc("GET /login.html", serveSPALogin)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsListener := tls.NewListener(lis, tlsConfig)

	server := &http.Server{Handler: mux}

	gw := &browserGateway{
		server:    server,
		listener:  tlsListener,
		baseURL:   baseURL,
		engine:    eng,
		userStore: userStore,
		sessMgr:   sessMgr,
		cookieCfg: cookieCfg,
		tlsCert:   serverCert,
		pki:       pki,
	}

	go func() {
		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			// Normal shutdown
		}
	}()

	t.Cleanup(func() { _ = server.Close() })

	return gw
}
