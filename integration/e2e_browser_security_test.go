// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0039: Playwright E2E — Browser Security (CSRF, CORS, XSS, Cookies)
//
// Go-native HTTP client tests verifying browser security properties:
// SameSite cookie CSRF protection, HttpOnly flags, CORS enforcement,
// XSS reflection prevention, OAuth state tampering, and cookie scoping.
package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---------- CSRF Protection ----------

// TestE2E_Security_SameSite_CookieCSRF verifies:
// AC: Cross-site form POST → blocked by SameSite cookie
//
// SameSite=Strict cookies are NOT sent on cross-origin requests.
// We verify the auth_session cookie has SameSite=Strict.
func TestE2E_Security_SameSite_CookieCSRF(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "csrf@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login to get a session cookie.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"csrf@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	// Verify the session cookie has SameSite=Strict.
	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie SameSite = %v, want Strict (CSRF protection)", sessionCookie.SameSite)
	}

	// Verify the Set-Cookie header string explicitly includes SameSite=Strict.
	setCookieHeaders := loginResp.Header.Values("Set-Cookie")
	foundStrict := false
	for _, h := range setCookieHeaders {
		if strings.Contains(h, "auth_session") && strings.Contains(h, "SameSite=Strict") {
			foundStrict = true
			break
		}
	}
	if !foundStrict {
		t.Errorf("Set-Cookie header for auth_session must include SameSite=Strict; got headers: %v", setCookieHeaders)
	}

	// Simulate cross-site request: POST /auth/logout without cookies
	// (as if from a different origin — SameSite=Strict prevents cookie attachment).
	logoutResp, err := client.Post(gw.baseURL+"/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("cross-site logout: %v", err)
	}
	logoutResp.Body.Close()

	// Without cookies, the server should reject with 401.
	if logoutResp.StatusCode != 401 {
		t.Errorf("cross-site POST without cookies should get 401, got %d", logoutResp.StatusCode)
	}
}

// ---------- HttpOnly Cookie ----------

// TestE2E_Security_HttpOnly_Cookie verifies:
// AC: Session cookie NOT accessible via JavaScript (HttpOnly verified)
func TestE2E_Security_HttpOnly_Cookie(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "httponly@example.com", "StrongPass123!")

	client := gw.httpClient()

	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"httponly@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	// Check HttpOnly flag on the session cookie.
	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	if !sessionCookie.HttpOnly {
		t.Error("session cookie MUST be HttpOnly (prevents document.cookie access)")
	}

	// Also verify via raw Set-Cookie header.
	setCookieHeaders := loginResp.Header.Values("Set-Cookie")
	foundHttpOnly := false
	for _, h := range setCookieHeaders {
		if strings.Contains(h, "auth_session") && strings.Contains(h, "HttpOnly") {
			foundHttpOnly = true
			break
		}
	}
	if !foundHttpOnly {
		t.Errorf("Set-Cookie header must include HttpOnly; got: %v", setCookieHeaders)
	}
}

// ---------- CORS ----------

// TestE2E_Security_CORS_NoHeaders verifies:
// AC: Fetch from different origin without CORS headers → blocked
//
// Without CORS middleware configured, the server won't include
// Access-Control-Allow-Origin headers. Browsers will block such responses.
func TestE2E_Security_CORS_NoHeaders(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	// Send a request with an Origin header (simulating cross-origin fetch).
	req, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	req.Header.Set("Origin", "https://evil.com")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/me with Origin: %v", err)
	}
	defer resp.Body.Close()

	// The server should NOT include Access-Control-Allow-Origin for unknown origins.
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "https://evil.com" || acao == "*" {
		t.Errorf("server should NOT allow cross-origin access from evil.com; ACAO = %q", acao)
	}

	// Access-Control-Allow-Credentials must also be absent for unknown origins.
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	if acac != "" {
		t.Errorf("Access-Control-Allow-Credentials should be absent for evil.com; got %q", acac)
	}

	// Preflight (OPTIONS) should also not include CORS headers for unknown origin.
	optReq, _ := http.NewRequest("OPTIONS", gw.baseURL+"/api/me", nil)
	optReq.Header.Set("Origin", "https://evil.com")
	optReq.Header.Set("Access-Control-Request-Method", "GET")

	optResp, err := client.Do(optReq)
	if err != nil {
		t.Fatalf("OPTIONS /api/me: %v", err)
	}
	optResp.Body.Close()

	optACAO := optResp.Header.Get("Access-Control-Allow-Origin")
	if optACAO == "https://evil.com" || optACAO == "*" {
		t.Errorf("OPTIONS should NOT include ACAO for evil.com; got %q", optACAO)
	}

	// Preflight must also not expose credentials.
	optACAC := optResp.Header.Get("Access-Control-Allow-Credentials")
	if optACAC != "" {
		t.Errorf("OPTIONS Access-Control-Allow-Credentials should be absent for evil.com; got %q", optACAC)
	}
}

// TestE2E_Security_CORS_SameOrigin verifies:
// AC: Fetch from allowed origin → succeeds
//
// Same-origin requests (no Origin header or matching origin) should work normally.
func TestE2E_Security_CORS_SameOrigin(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "sameorigin@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"sameorigin@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// Same-origin request (no Origin header — browser same-origin behavior).
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)

	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		t.Fatalf("same-origin request status = %d, want 200", meResp.StatusCode)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)
	if meData["subject_id"] != "sameorigin@example.com" {
		t.Errorf("subject_id = %v, want sameorigin@example.com", meData["subject_id"])
	}
}

// ---------- XSS Reflection ----------

// TestE2E_Security_XSS_NoReflection verifies:
// AC: Script tags in login form fields → not reflected in error messages
func TestE2E_Security_XSS_NoReflection(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	// Attempt login with script tags in the identifier.
	xssPayload := `<script>alert('xss')</script>@example.com`
	loginBody := `{"identifier":"` + xssPayload + `","password":"anything"}`

	resp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(loginBody),
	)
	if err != nil {
		t.Fatalf("POST /auth/login with XSS payload: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// The error response must NOT reflect the script tag.
	if strings.Contains(bodyStr, "<script>") {
		t.Errorf("error response REFLECTS script tag (XSS vulnerability): %s", bodyStr)
	}
	if strings.Contains(bodyStr, "alert(") {
		t.Errorf("error response REFLECTS alert() (XSS vulnerability): %s", bodyStr)
	}

	// The response should be a generic error, not echoing back input.
	expectedBody := "Unauthorized"
	if strings.TrimSpace(bodyStr) != expectedBody {
		t.Errorf("login response body = %q, want exactly %q (must not reflect input)", bodyStr, expectedBody)
	}

	// Also test XSS in the registration path.
	// The register endpoint creates the user with the submitted identifier.
	// Even if the identifier contains HTML, the JSON response should escape it
	// properly (Go's json.Encoder escapes <, >, & by default).
	regBody := `{"identifier":"<img src=x onerror=alert(1)>@test.com","password":"StrongPass123!"}`
	regResp, err := client.Post(
		gw.baseURL+"/auth/register",
		"application/json",
		strings.NewReader(regBody),
	)
	if err != nil {
		t.Fatalf("POST /auth/register with XSS: %v", err)
	}
	defer regResp.Body.Close()

	regBodyBytes, _ := io.ReadAll(regResp.Body)
	regStr := string(regBodyBytes)

	// The raw HTML must NOT appear unescaped in the response.
	// Go's json.Encoder converts < to \u003c, which is safe.
	if strings.Contains(regStr, "<img") {
		t.Errorf("register response contains raw HTML tag (XSS): %s", regStr)
	}
	if strings.Contains(regStr, "<script") {
		t.Errorf("register response contains raw script tag (XSS): %s", regStr)
	}
	// Verify JSON encoding escapes HTML entities.
	if regResp.StatusCode == 201 && !strings.Contains(regStr, `\u003c`) {
		t.Errorf("JSON response should HTML-escape < to \\u003c for XSS safety")
	}
}

// ---------- OAuth State Tampering ----------

// TestE2E_Security_OAuthState_Tampering verifies:
// AC: OAuth state cookie tampering → callback fails
func TestE2E_Security_OAuthState_Tampering(t *testing.T) {
	pki := newTestPKI(t)
	kc := startKeycloak(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki:      pki,
		keycloak: kc,
	})

	client := gw.httpClient()

	// Initiate OAuth to get a real state token.
	resp, err := client.Get(gw.baseURL + "/auth/oauth/keycloak")
	if err != nil {
		t.Fatalf("GET /auth/oauth/keycloak: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("initiate status = %d, want 302", resp.StatusCode)
	}

	// Try to hit the callback with a tampered state.
	tamperedState := "tampered-state-value"
	callbackURL := gw.baseURL + "/auth/oauth/keycloak/callback?code=fake-code&state=" + tamperedState

	// Create a request with a tampered oauth_state cookie.
	callbackReq, _ := http.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(&http.Cookie{
		Name:  "oauth_state",
		Value: "different-state-value", // doesn't match the state param
	})

	callbackResp, err := client.Do(callbackReq)
	if err != nil {
		t.Fatalf("GET callback with tampered state: %v", err)
	}
	defer callbackResp.Body.Close()

	// Must reject — state mismatch.
	if callbackResp.StatusCode != 401 {
		t.Fatalf("tampered OAuth state should get 401, got %d", callbackResp.StatusCode)
	}

	body, _ := io.ReadAll(callbackResp.Body)
	if !strings.Contains(string(body), "state mismatch") {
		t.Errorf("error should mention state mismatch, got: %s", string(body))
	}
}

// TestE2E_Security_OAuthState_MissingCookie verifies state validation
// when the oauth_state cookie is completely absent.
func TestE2E_Security_OAuthState_MissingCookie(t *testing.T) {
	pki := newTestPKI(t)
	kc := startKeycloak(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki:      pki,
		keycloak: kc,
	})

	client := gw.httpClient()

	// Hit callback without any state cookie.
	callbackURL := gw.baseURL + "/auth/oauth/keycloak/callback?code=fake-code&state=any-state"
	callbackResp, err := client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback without state cookie: %v", err)
	}
	defer callbackResp.Body.Close()

	if callbackResp.StatusCode != 401 {
		t.Fatalf("missing OAuth state cookie should get 401, got %d", callbackResp.StatusCode)
	}
}

// ---------- Cookie Domain Scoping ----------

// TestE2E_Security_CookieDomainScoping verifies:
// AC: Session cookie scoped to correct domain, not leaking to subdomains
func TestE2E_Security_CookieDomainScoping(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "scope@example.com", "StrongPass123!")

	client := gw.httpClient()

	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"scope@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// Domain should NOT be set to a wildcard or broad domain.
	// An empty Domain means the cookie is scoped to the exact host (most secure).
	// If Domain is set, it should be the specific host, not a parent domain.
	if sessionCookie.Domain != "" && sessionCookie.Domain != "localhost" {
		t.Errorf("session cookie Domain = %q, want empty (exact host) or 'localhost'", sessionCookie.Domain)
	}

	// Path should be "/".
	if sessionCookie.Path != "/" {
		t.Errorf("session cookie Path = %q, want '/'", sessionCookie.Path)
	}

	// Secure flag must be set (HTTPS only — prevents leak over HTTP).
	if !sessionCookie.Secure {
		t.Error("session cookie must have Secure flag (HTTPS only)")
	}
}

// ---------- Cookie Security Comprehensive ----------

// TestE2E_Security_CookieFlags_Comprehensive verifies all cookie security
// attributes are correctly set on both login and registration responses.
func TestE2E_Security_CookieFlags_Comprehensive(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	// Register (also sets cookie).
	regResp, err := client.Post(
		gw.baseURL+"/auth/register",
		"application/json",
		strings.NewReader(`{"identifier":"flags@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	regResp.Body.Close()

	regCookie := findHTTPCookie(regResp, "auth_session")
	if regCookie == nil {
		t.Fatal("no session cookie after registration")
	}

	// Verify all security attributes on registration cookie.
	checks := []struct {
		name string
		ok   bool
		msg  string
	}{
		{"HttpOnly", regCookie.HttpOnly, "cookie must be HttpOnly"},
		{"Secure", regCookie.Secure, "cookie must be Secure"},
		{"SameSite=Strict", regCookie.SameSite == http.SameSiteStrictMode, "cookie must be SameSite=Strict"},
		{"Path=/", regCookie.Path == "/", "cookie Path must be /"},
	}

	for _, c := range checks {
		if !c.ok {
			t.Errorf("registration cookie: %s — %s", c.name, c.msg)
		}
	}

	// Verify logout cookie also has correct attributes.
	logoutReq, _ := http.NewRequest("POST", gw.baseURL+"/auth/logout", nil)
	logoutReq.AddCookie(regCookie)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	logoutResp.Body.Close()

	clearedCookie := findHTTPCookie(logoutResp, "auth_session")
	if clearedCookie == nil {
		t.Fatal("no cleared cookie on logout")
	}

	if clearedCookie.MaxAge >= 0 {
		t.Errorf("logout cookie MaxAge = %d, want < 0", clearedCookie.MaxAge)
	}
	if !clearedCookie.HttpOnly {
		t.Error("cleared cookie must still be HttpOnly")
	}
	if !clearedCookie.Secure {
		t.Error("cleared cookie must still be Secure")
	}
}

// ---------- OAuth State Cookie Attributes ----------

// TestE2E_Security_OAuthStateCookie_Attributes verifies:
// OAuth state cookie uses SameSite=Lax (required for cross-origin redirect flow).
func TestE2E_Security_OAuthStateCookie_Attributes(t *testing.T) {
	pki := newTestPKI(t)
	kc := startKeycloak(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki:      pki,
		keycloak: kc,
	})

	client := gw.httpClient()

	resp, err := client.Get(gw.baseURL + "/auth/oauth/keycloak")
	if err != nil {
		t.Fatalf("GET /auth/oauth/keycloak: %v", err)
	}
	resp.Body.Close()

	stateCookie := findHTTPCookie(resp, "oauth_state")
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie")
	}

	// OAuth state cookie must be SameSite=Lax (for cross-origin redirect).
	if stateCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("oauth_state SameSite = %v, want Lax (required for OAuth redirect flow)", stateCookie.SameSite)
	}

	// Must be HttpOnly.
	if !stateCookie.HttpOnly {
		t.Error("oauth_state cookie must be HttpOnly")
	}

	// Must be Secure.
	if !stateCookie.Secure {
		t.Error("oauth_state cookie must be Secure")
	}

	// Should have a MaxAge (10 minutes = 600s).
	if stateCookie.MaxAge <= 0 || stateCookie.MaxAge > 600 {
		t.Errorf("oauth_state MaxAge = %d, want >0 and ≤600", stateCookie.MaxAge)
	}
}
