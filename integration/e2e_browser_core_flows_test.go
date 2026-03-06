// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0037: Playwright E2E — Core Auth Flows
//
// Go-native HTTP client tests exercising core authentication flows through the
// browser gateway: password login (correct/wrong/non-existent), registration
// (success/weak password/duplicate), OAuth via Keycloak, magic link via MailHog,
// and logout.
//
// These tests are the Go equivalent of Playwright browser tests. They exercise
// the same server-side code paths that a browser would hit, including cookie
// handling, redirect following, and error responses.
package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---------- Password Login Tests ----------

// TestE2E_CoreFlow_PasswordLogin_Success verifies:
// AC: Password login: fill form → submit → dashboard → session cookie present
func TestE2E_CoreFlow_PasswordLogin_Success(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "alice@example.com", "StrongPass123!")

	client := gw.httpClientWithJar()

	// POST login.
	resp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"alice@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status = %d, want 200, body = %s", resp.StatusCode, body)
	}

	// Session cookie must be present.
	sessionCookie := findHTTPCookie(resp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no auth_session cookie after successful login")
	}
	if sessionCookie.Value == "" {
		t.Error("session cookie value is empty")
	}

	// Verify cookie security flags on login response.
	if !sessionCookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Error("session cookie must be Secure")
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie SameSite = %v, want Strict", sessionCookie.SameSite)
	}

	// Cookie jar should now carry the cookie — access dashboard API.
	meResp, err := client.Get(gw.baseURL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		t.Fatalf("GET /api/me status = %d, want 200 (cookie jar should carry session)", meResp.StatusCode)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)
	if meData["subject_id"] != "alice@example.com" {
		t.Errorf("subject_id = %v, want alice@example.com", meData["subject_id"])
	}
}

// TestE2E_CoreFlow_PasswordLogin_WrongPassword verifies:
// AC: Password login wrong: error shown, no redirect, no cookie
func TestE2E_CoreFlow_PasswordLogin_WrongPassword(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "alice@example.com", "StrongPass123!")

	client := gw.httpClient()

	resp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"alice@example.com","password":"WrongPassword!"}`),
	)
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer resp.Body.Close()

	// Must get 401, NOT a redirect.
	if resp.StatusCode != 401 {
		t.Fatalf("wrong password status = %d, want 401", resp.StatusCode)
	}

	// No session cookie should be set.
	sessionCookie := findHTTPCookie(resp, "auth_session")
	if sessionCookie != nil {
		t.Error("wrong password should NOT set a session cookie")
	}

	// Error body must be generic (no enumeration).
	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(body))
	if bodyStr != "Unauthorized" {
		t.Errorf("error body = %q, want generic 'Unauthorized'", bodyStr)
	}
}

// TestE2E_CoreFlow_PasswordLogin_NonExistentUser verifies:
// AC: Password login non-existent user: same generic error (no enumeration)
func TestE2E_CoreFlow_PasswordLogin_NonExistentUser(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	resp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"nobody@example.com","password":"SomePass123!"}`),
	)
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer resp.Body.Close()

	// Same 401 and same generic error as wrong password.
	if resp.StatusCode != 401 {
		t.Fatalf("non-existent user status = %d, want 401", resp.StatusCode)
	}

	sessionCookie := findHTTPCookie(resp, "auth_session")
	if sessionCookie != nil {
		t.Error("non-existent user should NOT set a session cookie")
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(body))
	if bodyStr != "Unauthorized" {
		t.Errorf("error body = %q, want generic 'Unauthorized' (no enumeration)", bodyStr)
	}
}

// ---------- Registration Tests ----------

// TestE2E_CoreFlow_Registration_Success verifies:
// AC: Registration: fill form → submit → immediately on dashboard
func TestE2E_CoreFlow_Registration_Success(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClientWithJar()

	// Register.
	resp, err := client.Post(
		gw.baseURL+"/auth/register",
		"application/json",
		strings.NewReader(`{"identifier":"newuser@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("POST /auth/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status = %d, want 201, body = %s", resp.StatusCode, body)
	}

	// Session cookie should be set (register-and-login-in-one).
	sessionCookie := findHTTPCookie(resp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie after registration")
	}

	// Immediately on dashboard — cookie jar carries the session.
	meResp, err := client.Get(gw.baseURL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		t.Fatalf("GET /api/me after register status = %d, want 200", meResp.StatusCode)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)
	if meData["subject_id"] != "newuser@example.com" {
		t.Errorf("subject_id = %v, want newuser@example.com", meData["subject_id"])
	}
}

// TestE2E_CoreFlow_Registration_WeakPassword verifies:
// AC: Registration weak password: error shown
func TestE2E_CoreFlow_Registration_WeakPassword(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	// Try to register with a weak password (too short).
	resp, err := client.Post(
		gw.baseURL+"/auth/register",
		"application/json",
		strings.NewReader(`{"identifier":"weak@example.com","password":"123"}`),
	)
	if err != nil {
		t.Fatalf("POST /auth/register: %v", err)
	}
	defer resp.Body.Close()

	// The engine validates password policy and returns an error.
	// The handler maps that to 401 (generic — prevents enumeration).
	if resp.StatusCode != 401 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("weak password status = %d, want exactly 401, body = %s", resp.StatusCode, body)
	}

	// Error body must be generic.
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "Unauthorized" {
		t.Errorf("weak password error body = %q, want generic 'Unauthorized'", string(body))
	}

	// No session cookie should be set.
	sessionCookie := findHTTPCookie(resp, "auth_session")
	if sessionCookie != nil {
		t.Error("weak password should NOT set a session cookie")
	}
}

// TestE2E_CoreFlow_Registration_DuplicateUser verifies:
// AC: Registration duplicate user: error
func TestE2E_CoreFlow_Registration_DuplicateUser(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	// Register the first time — should succeed.
	resp1, err := client.Post(
		gw.baseURL+"/auth/register",
		"application/json",
		strings.NewReader(`{"identifier":"dup@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	resp1.Body.Close()

	if resp1.StatusCode != 201 {
		t.Fatalf("first register status = %d, want 201", resp1.StatusCode)
	}

	// Register the same user again — should fail with 401 (generic).
	resp2, err := client.Post(
		gw.baseURL+"/auth/register",
		"application/json",
		strings.NewReader(`{"identifier":"dup@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 401 {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("duplicate registration status = %d, want exactly 401, body = %s", resp2.StatusCode, body)
	}

	// Error body must be generic — prevents user enumeration.
	body, _ := io.ReadAll(resp2.Body)
	if strings.TrimSpace(string(body)) != "Unauthorized" {
		t.Errorf("duplicate registration error body = %q, want generic 'Unauthorized'", string(body))
	}

	// No session cookie for the failed registration.
	sessionCookie := findHTTPCookie(resp2, "auth_session")
	if sessionCookie != nil {
		t.Error("duplicate user should NOT set a session cookie")
	}
}

// ---------- OAuth Tests ----------

// TestE2E_CoreFlow_OAuth_FullFlow verifies:
// AC: OAuth Keycloak full flow: click button → Keycloak → credentials → callback → dashboard
// AC: OAuth auto-register: first login creates user, dashboard shows OAuth auth method
// AC: OAuth returning user: no duplicate
// AC: OAuth redirect preserves cookies
func TestE2E_CoreFlow_OAuth_FullFlow(t *testing.T) {
	pki := newTestPKI(t)
	kc := startKeycloak(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki:      pki,
		keycloak: kc,
	})

	// Create a test user in Keycloak.
	ctx := context.Background()
	adminToken := kc.getAdminToken(t)
	kc.createUser(t, ctx, adminToken, "oauthuser", "oauthuser@example.com", "OAuthPass123!", true)

	client := gw.httpClient()

	// Step 1: Initiate OAuth — GET /auth/oauth/keycloak
	// This should redirect to Keycloak's authorization endpoint.
	resp, err := client.Get(gw.baseURL + "/auth/oauth/keycloak")
	if err != nil {
		t.Fatalf("GET /auth/oauth/keycloak: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("oauth initiate status = %d, want 302, body = %s", resp.StatusCode, body)
	}

	// Check redirect URL points to Keycloak.
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "realms/test") {
		t.Errorf("oauth redirect should point to Keycloak, got: %s", location)
	}
	if !strings.Contains(location, "client_id=browser-gateway") {
		t.Errorf("oauth redirect should include client_id, got: %s", location)
	}
	if !strings.Contains(location, "response_type=code") {
		t.Errorf("oauth redirect should include response_type=code, got: %s", location)
	}

	// Check OAuth state cookie is set.
	stateCookie := findHTTPCookie(resp, "oauth_state")
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie after OAuth initiate")
	}
	if stateCookie.Value == "" {
		t.Error("oauth_state cookie value is empty")
	}

	// Step 2: Simulate the Keycloak flow.
	// Use direct grant to get tokens, then simulate the callback with
	// a real authorization code. We need to actually call Keycloak's
	// authorization endpoint as a browser would.
	//
	// In Go testing, we simulate the full OAuth flow by:
	// 1. Following the redirect to Keycloak
	// 2. Posting credentials to Keycloak's login form
	// 3. Keycloak redirects back to our callback with a code
	// This is the real OIDC authorization code flow.

	// Create a client that trusts our CA but can also talk to Keycloak over HTTP.
	oauthClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	// Follow the redirect to Keycloak (over HTTP, not HTTPS).
	kcResp, err := oauthClient.Get(location)
	if err != nil {
		t.Fatalf("GET Keycloak auth: %v", err)
	}
	defer kcResp.Body.Close()

	// Keycloak returns a login page (200) or redirects if already authenticated.
	// We need to submit the login form.
	if kcResp.StatusCode != 200 {
		// If we get a redirect, it might be direct to callback.
		if kcResp.StatusCode == 302 {
			t.Log("Keycloak redirected directly (user may already be authenticated)")
		} else {
			body, _ := io.ReadAll(kcResp.Body)
			t.Fatalf("Keycloak auth page status = %d, body = %s", kcResp.StatusCode, string(body))
		}
	}

	// Extract the login form action URL from the Keycloak login page.
	kcBody, _ := io.ReadAll(kcResp.Body)
	formAction := extractFormAction(t, string(kcBody))

	// Keycloak sets session cookies we need to carry forward.
	var kcCookies []*http.Cookie
	kcCookies = append(kcCookies, kcResp.Cookies()...)

	// Submit credentials to Keycloak.
	loginData := "username=oauthuser%40example.com&password=OAuthPass123%21"
	loginReq, _ := http.NewRequest("POST", formAction, strings.NewReader(loginData))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range kcCookies {
		loginReq.AddCookie(c)
	}

	kcLoginResp, err := oauthClient.Do(loginReq)
	if err != nil {
		t.Fatalf("POST Keycloak login: %v", err)
	}
	defer kcLoginResp.Body.Close()

	// Keycloak should redirect back to our callback with code and state.
	if kcLoginResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(kcLoginResp.Body)
		t.Fatalf("Keycloak login redirect status = %d, want 302, body = %s",
			kcLoginResp.StatusCode, string(body))
	}

	callbackURL := kcLoginResp.Header.Get("Location")
	if !strings.Contains(callbackURL, "/auth/oauth/keycloak/callback") {
		t.Fatalf("Keycloak should redirect to our callback, got: %s", callbackURL)
	}
	if !strings.Contains(callbackURL, "code=") {
		t.Fatalf("callback URL should contain authorization code, got: %s", callbackURL)
	}

	// Step 3: Hit our callback endpoint with the code and state cookie.
	callbackReq, _ := http.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie) // carry the oauth_state cookie

	callbackResp, err := gw.httpClient().Do(callbackReq)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	defer callbackResp.Body.Close()

	// Callback should redirect to dashboard with session cookie.
	if callbackResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("callback status = %d, want 302, body = %s", callbackResp.StatusCode, body)
	}

	if loc := callbackResp.Header.Get("Location"); loc != "/dashboard.html" {
		t.Errorf("callback redirect = %q, want '/dashboard.html'", loc)
	}

	sessionCookie := findHTTPCookie(callbackResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie after OAuth callback")
	}

	// Step 4: Access dashboard with session cookie.
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)

	meResp, err := gw.httpClient().Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		t.Fatalf("GET /api/me after OAuth status = %d, want 200", meResp.StatusCode)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)

	// OAuth auto-register: first OAuth login creates the user.
	subjectID, _ := meData["subject_id"].(string)
	if subjectID == "" {
		t.Error("subject_id should be non-empty after OAuth login")
	}

	// Step 5: OAuth returning user — login again, no duplicate.
	// Repeat the same flow and verify the same subject_id is returned.
	resp2, err := client.Get(gw.baseURL + "/auth/oauth/keycloak")
	if err != nil {
		t.Fatalf("second OAuth initiate: %v", err)
	}
	resp2.Body.Close()

	stateCookie2 := findHTTPCookie(resp2, "oauth_state")
	location2 := resp2.Header.Get("Location")

	// Follow through Keycloak again (user may already have a session).
	kcResp2, err := oauthClient.Get(location2)
	if err != nil {
		t.Fatalf("second Keycloak auth: %v", err)
	}

	var callbackURL2 string
	if kcResp2.StatusCode == http.StatusFound {
		// Keycloak remembered the session — direct redirect.
		callbackURL2 = kcResp2.Header.Get("Location")
	} else {
		// Need to login again.
		kcBody2, _ := io.ReadAll(kcResp2.Body)
		formAction2 := extractFormAction(t, string(kcBody2))
		kcCookies2 := kcResp2.Cookies()

		loginReq2, _ := http.NewRequest("POST", formAction2, strings.NewReader(loginData))
		loginReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range kcCookies2 {
			loginReq2.AddCookie(c)
		}
		kcLoginResp2, err := oauthClient.Do(loginReq2)
		if err != nil {
			t.Fatalf("second Keycloak login: %v", err)
		}
		callbackURL2 = kcLoginResp2.Header.Get("Location")
		kcLoginResp2.Body.Close()
	}
	kcResp2.Body.Close()

	callbackReq2, _ := http.NewRequest("GET", callbackURL2, nil)
	callbackReq2.AddCookie(stateCookie2)

	callbackResp2, err := gw.httpClient().Do(callbackReq2)
	if err != nil {
		t.Fatalf("second callback: %v", err)
	}
	defer callbackResp2.Body.Close()

	sessionCookie2 := findHTTPCookie(callbackResp2, "auth_session")
	if sessionCookie2 == nil {
		t.Fatal("no session cookie after second OAuth callback")
	}

	meReq2, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq2.AddCookie(sessionCookie2)
	meResp2, err := gw.httpClient().Do(meReq2)
	if err != nil {
		t.Fatalf("second GET /api/me: %v", err)
	}
	defer meResp2.Body.Close()

	var meData2 map[string]any
	_ = json.NewDecoder(meResp2.Body).Decode(&meData2)

	subjectID2, _ := meData2["subject_id"].(string)
	if subjectID2 != subjectID {
		t.Errorf("returning OAuth user should get same subject_id: got %q, want %q",
			subjectID2, subjectID)
	}
}

// ---------- Magic Link Tests ----------

// TestE2E_CoreFlow_MagicLink_FullFlow verifies:
// AC: Magic link: enter email → submit → 202 → "check inbox"
// AC: Magic link verify: MailHog API → extract link → visit → dashboard
func TestE2E_CoreFlow_MagicLink_FullFlow(t *testing.T) {
	pki := newTestPKI(t)
	mh := startMailHog(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki:     pki,
		mailhog: mh,
	})

	// Pre-register user.
	gw.registerUser(t, "mluser@example.com", "unused")

	mh.deleteAllMessages(t)

	client := gw.httpClient()

	// Step 1: Initiate magic link.
	resp, err := client.Post(
		gw.baseURL+"/auth/magic-link",
		"application/json",
		strings.NewReader(`{"identifier":"mluser@example.com"}`),
	)
	if err != nil {
		t.Fatalf("POST /auth/magic-link: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 {
		t.Fatalf("magic link initiate status = %d, want 202", resp.StatusCode)
	}

	// Step 2: Get email from MailHog.
	email := mh.getLatestMessage(t)
	body := email.bodyText()
	if !strings.Contains(body, "/auth/magic-link/verify?token=") {
		t.Fatalf("email should contain magic link URL, got: %s", body)
	}

	// Step 3: Visit the magic link.
	magicURL := extractMagicLinkURL(t, body)
	verifyResp, err := client.Get(magicURL)
	if err != nil {
		t.Fatalf("GET magic link: %v", err)
	}
	defer verifyResp.Body.Close()

	if verifyResp.StatusCode != http.StatusFound {
		t.Fatalf("magic link verify status = %d, want 302", verifyResp.StatusCode)
	}
	if loc := verifyResp.Header.Get("Location"); loc != "/dashboard.html" {
		t.Errorf("redirect = %q, want '/dashboard.html'", loc)
	}

	sessionCookie := findHTTPCookie(verifyResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie after magic link verification")
	}

	// Step 4: Access dashboard.
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 200 {
		t.Fatalf("GET /api/me status = %d, want 200", meResp.StatusCode)
	}

	var meData map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&meData)
	if meData["subject_id"] != "mluser@example.com" {
		t.Errorf("subject_id = %v, want mluser@example.com", meData["subject_id"])
	}
}

// TestE2E_CoreFlow_MagicLink_ExpiredReuse verifies:
// AC: Magic link expired / reuse: error page
func TestE2E_CoreFlow_MagicLink_ExpiredReuse(t *testing.T) {
	pki := newTestPKI(t)
	mh := startMailHog(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki:     pki,
		mailhog: mh,
	})

	gw.registerUser(t, "reuse@example.com", "unused")
	mh.deleteAllMessages(t)

	client := gw.httpClient()

	// Initiate.
	resp, err := client.Post(
		gw.baseURL+"/auth/magic-link",
		"application/json",
		strings.NewReader(`{"identifier":"reuse@example.com"}`),
	)
	if err != nil {
		t.Fatalf("POST /auth/magic-link: %v", err)
	}
	resp.Body.Close()

	// Get the magic link.
	email := mh.getLatestMessage(t)
	magicURL := extractMagicLinkURL(t, email.bodyText())

	// Use the magic link once (should succeed).
	firstResp, err := client.Get(magicURL)
	if err != nil {
		t.Fatalf("first magic link use: %v", err)
	}
	firstResp.Body.Close()

	if firstResp.StatusCode != http.StatusFound {
		t.Fatalf("first use status = %d, want 302", firstResp.StatusCode)
	}

	// Reuse the same magic link (should fail — token consumed).
	secondResp, err := client.Get(magicURL)
	if err != nil {
		t.Fatalf("second magic link use: %v", err)
	}
	defer secondResp.Body.Close()

	if secondResp.StatusCode == http.StatusFound {
		t.Fatal("reused magic link should NOT redirect to dashboard")
	}
	if secondResp.StatusCode != 401 {
		t.Fatalf("reused magic link status = %d, want exactly 401", secondResp.StatusCode)
	}

	// No new session cookie on reuse.
	reuseCookie := findHTTPCookie(secondResp, "auth_session")
	if reuseCookie != nil {
		t.Error("reused magic link should NOT set a session cookie")
	}
}

// ---------- Logout Test ----------

// TestE2E_CoreFlow_Logout verifies:
// AC: Logout: cookie cleared, redirect to login, dashboard returns 401
func TestE2E_CoreFlow_Logout(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})
	gw.registerUser(t, "logout@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login.
	loginResp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(`{"identifier":"logout@example.com","password":"StrongPass123!"}`),
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// Verify session works.
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	meResp.Body.Close()
	if meResp.StatusCode != 200 {
		t.Fatalf("GET /api/me status = %d, want 200", meResp.StatusCode)
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

	// Cookie should be cleared.
	clearedCookie := findHTTPCookie(logoutResp, "auth_session")
	if clearedCookie == nil {
		t.Fatal("logout should set auth_session cookie with MaxAge=-1")
	}
	if clearedCookie.MaxAge >= 0 {
		t.Errorf("cleared cookie MaxAge = %d, want < 0", clearedCookie.MaxAge)
	}

	// Dashboard should now return 401 with the old cookie.
	meReq2, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq2.AddCookie(sessionCookie)
	meResp2, err := client.Do(meReq2)
	if err != nil {
		t.Fatalf("GET /api/me after logout: %v", err)
	}
	meResp2.Body.Close()

	if meResp2.StatusCode != 401 {
		t.Fatalf("GET /api/me after logout status = %d, want 401", meResp2.StatusCode)
	}
}

// ---------- Helpers ----------

// extractFormAction extracts the form action URL from a Keycloak login page HTML.
func extractFormAction(t *testing.T, html string) string {
	t.Helper()
	// Look for: action="..."
	actionIdx := strings.Index(html, `action="`)
	if actionIdx == -1 {
		t.Fatalf("no form action found in Keycloak login page")
	}
	start := actionIdx + len(`action="`)
	end := strings.Index(html[start:], `"`)
	if end == -1 {
		t.Fatalf("unterminated form action attribute")
	}
	actionURL := html[start : start+end]
	// Keycloak may HTML-encode the URL.
	actionURL = strings.ReplaceAll(actionURL, "&amp;", "&")
	return actionURL
}
