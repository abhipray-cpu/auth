// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0036: SPA Test Application — Build & Serve
//
// This file provides the browser E2E test infrastructure:
//
//  1. MailHog testcontainer — captures magic link emails via SMTP, readable via REST API
//  2. In-process HTTP gateway — real net/http.Server with TLS, wiring engine + OAuth mode +
//     magic link mode + handlers + middleware + session cookies
//  3. Embedded SPA — vanilla JS served by the gateway (login, register, OAuth, magic link,
//     dashboard, logout)
//  4. In-memory OAuth StateStore — for server-side PKCE/state storage
//  5. In-memory MagicLinkStore — for magic link token storage
//  6. SMTP Notifier — sends magic link emails to MailHog
//
// The gateway serves the SPA at / and auth API endpoints at /auth/*.
// All auth flows go through the real engine → real modes → real session management.
package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	"github.com/abhipray-cpu/auth/hash"
	"github.com/abhipray-cpu/auth/hooks"
	authhttp "github.com/abhipray-cpu/auth/http"
	"github.com/abhipray-cpu/auth/mode/magiclink"
	"github.com/abhipray-cpu/auth/mode/oauth"
	modepw "github.com/abhipray-cpu/auth/mode/password"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ---------- MailHog Testcontainer ----------

// mailhogContainer holds the running MailHog instance.
type mailhogContainer struct {
	container testcontainers.Container
	smtpAddr  string // host:port for SMTP (1025)
	apiURL    string // http://host:port for REST API (8025)
}

// startMailHog starts a MailHog container for capturing magic link emails.
func startMailHog(t *testing.T) *mailhogContainer {
	t.Helper()
	skipIfNoDocker(t)

	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "mailhog/mailhog:v1.0.1",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor: wait.ForHTTP("/api/v2/messages").
			WithPort("8025/tcp").
			WithStartupTimeout(30 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start MailHog: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("mailhog host: %v", err)
	}
	smtpPort, err := ctr.MappedPort(ctx, "1025/tcp")
	if err != nil {
		t.Fatalf("mailhog smtp port: %v", err)
	}
	apiPort, err := ctr.MappedPort(ctx, "8025/tcp")
	if err != nil {
		t.Fatalf("mailhog api port: %v", err)
	}

	return &mailhogContainer{
		container: ctr,
		smtpAddr:  fmt.Sprintf("%s:%s", host, smtpPort.Port()),
		apiURL:    fmt.Sprintf("http://%s:%s", host, apiPort.Port()),
	}
}

// getLatestMessage retrieves the most recent email from MailHog.
// Returns the raw body text. Retries for up to 5 seconds.
func (mh *mailhogContainer) getLatestMessage(t *testing.T) mailhogMessage {
	t.Helper()

	var msgs mailhogMessages
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(mh.apiURL + "/api/v2/messages?limit=1")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		if err := json.NewDecoder(resp.Body).Decode(&msgs); err != nil {
			resp.Body.Close()
			time.Sleep(200 * time.Millisecond)
			continue
		}
		resp.Body.Close()

		if msgs.Total > 0 && len(msgs.Items) > 0 {
			return msgs.Items[0]
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Fatal("no messages in MailHog after 5s")
	return mailhogMessage{}
}

// deleteAllMessages clears all messages from MailHog.
func (mh *mailhogContainer) deleteAllMessages(t *testing.T) {
	t.Helper()
	req, _ := http.NewRequest("DELETE", mh.apiURL+"/api/v1/messages", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to delete MailHog messages: %v", err)
	}
	resp.Body.Close()
}

// mailhogMessages is the MailHog API response for listing messages.
type mailhogMessages struct {
	Total int              `json:"total"`
	Items []mailhogMessage `json:"items"`
}

// mailhogMessage represents a single email in MailHog.
type mailhogMessage struct {
	ID   string `json:"ID"`
	From struct {
		Mailbox string `json:"Mailbox"`
		Domain  string `json:"Domain"`
	} `json:"From"`
	To []struct {
		Mailbox string `json:"Mailbox"`
		Domain  string `json:"Domain"`
	} `json:"To"`
	Content struct {
		Headers map[string][]string `json:"Headers"`
		Body    string              `json:"Body"`
	} `json:"Content"`
	MIME struct {
		Parts []struct {
			Body string `json:"Body"`
		} `json:"Parts"`
	} `json:"MIME"`
}

// bodyText returns the email body text.
func (m *mailhogMessage) bodyText() string {
	// Try MIME parts first, then content body.
	if len(m.MIME.Parts) > 0 {
		return m.MIME.Parts[0].Body
	}
	return m.Content.Body
}

// ---------- SMTP Notifier (sends to MailHog) ----------

// smtpNotifier implements auth.Notifier by sending emails via SMTP.
type smtpNotifier struct {
	smtpAddr string
	fromAddr string
	baseURL  string // the gateway URL, for constructing magic link URLs
}

func newSMTPNotifier(smtpAddr, fromAddr, baseURL string) *smtpNotifier {
	return &smtpNotifier{
		smtpAddr: smtpAddr,
		fromAddr: fromAddr,
		baseURL:  baseURL,
	}
}

func (n *smtpNotifier) Notify(_ context.Context, event auth.AuthEvent, payload map[string]any) error {
	if event != auth.EventMagicLinkSent {
		return nil
	}

	identifier, _ := payload["identifier"].(string)
	token, _ := payload["token"].(string)
	if identifier == "" || token == "" {
		return fmt.Errorf("smtpNotifier: missing identifier or token")
	}

	// Build the magic link URL.
	magicLinkURL := fmt.Sprintf("%s/auth/magic-link/verify?token=%s", n.baseURL, url.QueryEscape(token))

	subject := "Your Magic Link"
	body := fmt.Sprintf("Click here to log in: %s", magicLinkURL)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain\r\n\r\n%s",
		n.fromAddr, identifier, subject, body)

	err := smtp.SendMail(n.smtpAddr, nil, n.fromAddr, []string{identifier}, []byte(msg))
	if err != nil {
		return fmt.Errorf("smtpNotifier: failed to send email: %w", err)
	}

	return nil
}

var _ auth.Notifier = (*smtpNotifier)(nil)

// ---------- In-memory OAuth StateStore ----------

// memOAuthStateStore implements oauth.StateStore in-memory.
type memOAuthStateStore struct {
	mu     sync.Mutex
	states map[string]*oauth.OAuthState
}

func newMemOAuthStateStore() *memOAuthStateStore {
	return &memOAuthStateStore{
		states: make(map[string]*oauth.OAuthState),
	}
}

func (s *memOAuthStateStore) Save(_ context.Context, state *oauth.OAuthState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

func (s *memOAuthStateStore) Load(_ context.Context, stateToken string) (*oauth.OAuthState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[stateToken]
	if !ok {
		return nil, fmt.Errorf("state not found: %s", stateToken)
	}
	// Single-use: delete after load.
	delete(s.states, stateToken)
	return st, nil
}

var _ oauth.StateStore = (*memOAuthStateStore)(nil)

// NOTE: memMagicLinkStore is defined in magiclink_apikey_test.go (same package).
// We reuse it here.

// ---------- Browser Test Gateway ----------

// browserGateway is a real HTTP server that serves the SPA and auth API.
type browserGateway struct {
	server    *http.Server
	listener  net.Listener
	baseURL   string // https://localhost:{port}
	engine    *engine.Engine
	oauthMode *oauth.Mode
	mlMode    *magiclink.Mode
	userStore *MemUserStore
	sessMgr   *session.Manager
	cookieCfg authhttp.CookieConfig
	tlsCert   *tlsCertPair
	pki       *tlsPKI
}

// browserGatewayConfig configures the browser test gateway.
type browserGatewayConfig struct {
	pki      *tlsPKI
	keycloak *keycloakContainer // nil if OAuth not needed
	mailhog  *mailhogContainer  // nil if magic link not needed
}

// startBrowserGateway starts a real HTTPS gateway with all auth flows wired.
func startBrowserGateway(t *testing.T, cfg browserGatewayConfig) *browserGateway {
	t.Helper()

	// Allocate a listener first to get the port.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("https://localhost:%d", port)

	// Issue server TLS cert.
	serverCert := cfg.pki.issueServerCert(t, "browser-gateway", "localhost")

	// Build stores.
	userStore := NewMemUserStore()
	sessStore := newMemSessionStore()
	sessMgr := session.NewManager(sessStore, session.DefaultConfig())
	oauthStateStore := newMemOAuthStateStore()
	magicLinkStore := newMemMagicLinkStore()

	// Build hasher.
	hasher := hash.NewArgon2idHasher(nil)

	// Build modes.
	var modes []auth.AuthMode
	var oauthMode *oauth.Mode
	var mlMode *magiclink.Mode

	// Password mode.
	pwMode := modepw.NewMode(modepw.ModeConfig{
		UserStore: userStore,
		Hasher:    hasher,
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
	})
	modes = append(modes, pwMode)

	// OAuth mode (if Keycloak available).
	if cfg.keycloak != nil {
		callbackURL := fmt.Sprintf("%s/auth/oauth/keycloak/callback", baseURL)

		// Create a confidential client in Keycloak for the browser gateway.
		token := cfg.keycloak.getAdminToken(t)
		clientSecret := "browser-gateway-secret"
		cfg.keycloak.createOAuthClient(t, token, "browser-gateway", clientSecret, callbackURL, baseURL)

		var modeErr error
		oauthMode, modeErr = oauth.NewMode(oauth.Config{
			UserStore:  userStore,
			StateStore: oauthStateStore,
			Providers: []oauth.ProviderConfig{
				{
					Name:         "keycloak",
					IssuerURL:    cfg.keycloak.issuerURL(),
					ClientID:     "browser-gateway",
					ClientSecret: clientSecret,
					RedirectURL:  callbackURL,
					Scopes:       []string{"openid", "profile", "email"},
				},
			},
		})
		if modeErr != nil {
			t.Fatalf("oauth.NewMode: %v", modeErr)
		}
		modes = append(modes, oauthMode)
	}

	// Magic link mode (if MailHog available).
	var notifier auth.Notifier
	if cfg.mailhog != nil {
		notifier = newSMTPNotifier(cfg.mailhog.smtpAddr, "auth@example.com", baseURL)

		var modeErr error
		mlMode, modeErr = magiclink.NewMode(magiclink.Config{
			UserStore:      userStore,
			MagicLinkStore: magicLinkStore,
			Notifier:       notifier,
			IdentifierConfig: auth.IdentifierConfig{
				Field:         "email",
				CaseSensitive: false,
				Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
			},
		})
		if modeErr != nil {
			t.Fatalf("magiclink.NewMode: %v", modeErr)
		}
		modes = append(modes, mlMode)
	}

	// Build engine.
	eng, err := engine.New(engine.Config{
		UserStore:      userStore,
		Hasher:         hasher,
		SessionManager: sessMgr,
		HookManager:    hooks.NewManager(),
		Notifier:       notifier,
		PasswordPolicy: pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
		Modes: modes,
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	// Build cookie config — Secure=false for tests using HTTP clients without TLS verification.
	// Real cookie security tests explicitly check Set-Cookie headers.
	cookieCfg := authhttp.CookieConfig{
		Name:     "auth_session",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	// Build HTTP mux.
	mux := http.NewServeMux()

	// Auth handlers wired through authhttp (for Login, Register, Logout).
	handlers := authhttp.NewHandlers(eng, cookieCfg)
	middleware := authhttp.NewMiddleware(eng, cookieCfg)

	// Mount standard auth routes.
	mux.Handle("POST /auth/login", handlers.Login())
	mux.Handle("POST /auth/register", handlers.Register())
	mux.Handle("POST /auth/logout", handlers.Logout())

	// OAuth initiate — we call oauthMode.BuildAuthURL directly
	// (the engine doesn't expose initiate; it only dispatches Authenticate).
	if oauthMode != nil {
		mux.HandleFunc("GET /auth/oauth/{provider}", func(w http.ResponseWriter, r *http.Request) {
			provider := r.PathValue("provider")
			if provider == "" {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			redirectURL, stateToken, err := oauthMode.BuildAuthURL(r.Context(), provider)
			if err != nil {
				http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Store state in cookie (SameSite=Lax for cross-origin redirect).
			authhttp.SetOAuthStateCookiePublic(w, "oauth_state", stateToken, cookieCfg)

			http.Redirect(w, r, redirectURL, http.StatusFound)
		})

		// OAuth callback — validate state cookie, exchange code via engine.
		mux.HandleFunc("GET /auth/oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
			provider := r.PathValue("provider")
			code := r.URL.Query().Get("code")
			state := r.URL.Query().Get("state")

			if code == "" {
				http.Error(w, "Bad Request: missing code", http.StatusBadRequest)
				return
			}

			// Validate state against cookie.
			storedState := authhttp.ReadOAuthStateCookiePublic(r, "oauth_state")
			if state == "" || storedState == "" || state != storedState {
				http.Error(w, "Unauthorized: state mismatch", http.StatusUnauthorized)
				return
			}

			// Clear state cookie after use.
			authhttp.ClearOAuthStateCookiePublic(w, "oauth_state", cookieCfg)

			// Authenticate via engine → oauth mode.
			cred := auth.Credential{
				Type: auth.CredentialTypeOAuth,
				Metadata: map[string]any{
					"provider": provider,
					"action":   "callback",
					"code":     code,
					"state":    state,
				},
			}

			identity, _, err := eng.Login(r.Context(), cred)
			if err != nil {
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			authhttp.SetSessionCookiePublic(w, identity.SessionID, cookieCfg)

			// Redirect to dashboard.
			http.Redirect(w, r, "/dashboard.html", http.StatusFound)
		})
	}

	// Magic link initiate — calls mlMode.Initiate directly.
	if mlMode != nil {
		mux.HandleFunc("POST /auth/magic-link", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Identifier string `json:"identifier"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Identifier == "" {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			// Fire and forget — always return 202 to prevent enumeration.
			_, _ = mlMode.Initiate(r.Context(), req.Identifier)
			w.WriteHeader(http.StatusAccepted)
		})

		// Magic link verify — authenticate via engine.
		mux.HandleFunc("GET /auth/magic-link/verify", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			cred := auth.Credential{
				Type:   auth.CredentialTypeMagicLink,
				Secret: token,
			}

			identity, _, err := eng.Login(r.Context(), cred)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			authhttp.SetSessionCookiePublic(w, identity.SessionID, cookieCfg)

			http.Redirect(w, r, "/dashboard.html", http.StatusFound)
		})
	}

	// Protected API endpoint — returns identity as JSON.
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

	// SPA pages.
	mux.HandleFunc("GET /", serveSPAIndex)
	mux.HandleFunc("GET /dashboard.html", serveSPADashboard)
	mux.HandleFunc("GET /login.html", serveSPALogin)

	// TLS config.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsListener := tls.NewListener(lis, tlsConfig)

	server := &http.Server{
		Handler: mux,
	}

	gw := &browserGateway{
		server:    server,
		listener:  tlsListener,
		baseURL:   baseURL,
		engine:    eng,
		oauthMode: oauthMode,
		mlMode:    mlMode,
		userStore: userStore,
		sessMgr:   sessMgr,
		cookieCfg: cookieCfg,
		tlsCert:   serverCert,
		pki:       cfg.pki,
	}

	// Start serving.
	go func() {
		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			// Server stopped normally.
		}
	}()

	t.Cleanup(func() {
		_ = server.Close()
	})

	return gw
}

// httpClient returns an *http.Client that trusts the gateway's CA and
// does NOT follow redirects (so we can inspect redirect responses).
func (gw *browserGateway) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: gw.pki.caPool,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}
}

// httpClientWithJar returns an *http.Client with a cookie jar that trusts
// the gateway's CA and follows redirects within the gateway (but not to
// external domains like Keycloak).
func (gw *browserGateway) httpClientWithJar() *http.Client {
	jar := &simpleCookieJar{cookies: make(map[string][]*http.Cookie)}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: gw.pki.caPool,
			},
		},
		Jar: jar,
	}
}

// registerUser pre-registers a user with a hashed password in the user store.
func (gw *browserGateway) registerUser(t *testing.T, identifier, password string) {
	t.Helper()
	hasher := hash.NewArgon2idHasher(nil)
	h, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	gw.userStore.AddUser(identifier, h)
}

// ---------- Simple Cookie Jar ----------

// simpleCookieJar is a minimal cookie jar for testing.
type simpleCookieJar struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie // keyed by host
}

func (j *simpleCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := u.Host
	existing := j.cookies[key]
	for _, newC := range cookies {
		found := false
		for i, oldC := range existing {
			if oldC.Name == newC.Name {
				existing[i] = newC
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, newC)
		}
	}
	j.cookies[key] = existing
}

func (j *simpleCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := u.Host
	var result []*http.Cookie
	for _, c := range j.cookies[key] {
		if c.MaxAge < 0 {
			continue // expired
		}
		result = append(result, c)
	}
	return result
}

// ---------- SPA Pages (embedded HTML) ----------

func serveSPAIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Explicitly no caching for auth-related pages.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	fmt.Fprint(w, spaIndexHTML)
}

func serveSPALogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	fmt.Fprint(w, spaLoginHTML)
}

func serveSPADashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// No-cache so back button after logout doesn't show cached authenticated page.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	fmt.Fprint(w, spaDashboardHTML)
}

// spaIndexHTML is the minimal landing page.
const spaIndexHTML = `<!DOCTYPE html>
<html>
<head><title>Auth Test SPA</title></head>
<body>
<h1>Auth Library Test SPA</h1>
<nav>
  <a href="/login.html">Login</a> |
  <a href="/dashboard.html">Dashboard</a>
</nav>
</body>
</html>`

// spaLoginHTML provides login, registration, OAuth, and magic link forms.
const spaLoginHTML = `<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h1>Login</h1>

<h2>Password Login</h2>
<form id="loginForm">
  <input type="email" id="loginEmail" name="identifier" placeholder="Email" required />
  <input type="password" id="loginPassword" name="password" placeholder="Password" required />
  <button type="submit">Login</button>
</form>
<div id="loginError" style="color:red"></div>
<div id="loginSuccess" style="color:green"></div>

<h2>Register</h2>
<form id="registerForm">
  <input type="email" id="regEmail" name="identifier" placeholder="Email" required />
  <input type="password" id="regPassword" name="password" placeholder="Password" required />
  <button type="submit">Register</button>
</form>
<div id="registerError" style="color:red"></div>

<h2>OAuth</h2>
<a id="oauthKeycloak" href="/auth/oauth/keycloak">Login with Keycloak</a>

<h2>Magic Link</h2>
<form id="magicLinkForm">
  <input type="email" id="mlEmail" name="identifier" placeholder="Email" required />
  <button type="submit">Send Magic Link</button>
</form>
<div id="magicLinkMessage"></div>

<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
  try {
    const resp = await fetch('/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({identifier: email, password: password})
    });
    if (resp.ok) {
      document.getElementById('loginSuccess').textContent = 'Login successful';
      window.location.href = '/dashboard.html';
    } else {
      const text = await resp.text();
      document.getElementById('loginError').textContent = text;
    }
  } catch (err) {
    document.getElementById('loginError').textContent = err.message;
  }
});

document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('regEmail').value;
  const password = document.getElementById('regPassword').value;
  try {
    const resp = await fetch('/auth/register', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({identifier: email, password: password})
    });
    if (resp.ok) {
      window.location.href = '/dashboard.html';
    } else {
      const text = await resp.text();
      document.getElementById('registerError').textContent = text;
    }
  } catch (err) {
    document.getElementById('registerError').textContent = err.message;
  }
});

document.getElementById('magicLinkForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('mlEmail').value;
  try {
    const resp = await fetch('/auth/magic-link', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({identifier: email})
    });
    if (resp.status === 202) {
      document.getElementById('magicLinkMessage').textContent = 'Check your inbox for the magic link.';
    }
  } catch (err) {
    document.getElementById('magicLinkMessage').textContent = err.message;
  }
});
</script>
</body>
</html>`

// spaDashboardHTML is the protected dashboard page.
const spaDashboardHTML = `<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>Dashboard</h1>
<div id="identity">Loading...</div>
<div id="error" style="color:red"></div>
<button id="logoutBtn">Logout</button>
<a href="/login.html">Back to Login</a>

<script>
async function loadIdentity() {
  try {
    const resp = await fetch('/api/me');
    if (resp.ok) {
      const data = await resp.json();
      document.getElementById('identity').innerHTML =
        '<strong>Subject:</strong> ' + data.subject_id + '<br/>' +
        '<strong>Auth Method:</strong> ' + data.auth_method + '<br/>' +
        '<strong>Session ID:</strong> ' + data.session_id;
    } else {
      document.getElementById('identity').textContent = '';
      document.getElementById('error').textContent = 'Not authenticated (HTTP ' + resp.status + ')';
    }
  } catch (err) {
    document.getElementById('error').textContent = err.message;
  }
}

document.getElementById('logoutBtn').addEventListener('click', async () => {
  try {
    const resp = await fetch('/auth/logout', {method: 'POST'});
    if (resp.ok || resp.status === 204) {
      window.location.href = '/login.html';
    } else {
      document.getElementById('error').textContent = 'Logout failed: ' + resp.status;
    }
  } catch (err) {
    document.getElementById('error').textContent = err.message;
  }
});

loadIdentity();
</script>
</body>
</html>`

// ---------- Keycloak Client Creation for Browser Gateway ----------

// createOAuthClient creates a confidential OAuth client in Keycloak.
func (kc *keycloakContainer) createOAuthClient(t *testing.T, token, clientID, clientSecret, redirectURI, webOrigin string) {
	t.Helper()
	ctx := context.Background()

	body := fmt.Sprintf(`{
		"clientId": %q,
		"enabled": true,
		"publicClient": false,
		"secret": %q,
		"directAccessGrantsEnabled": false,
		"redirectUris": [%q],
		"webOrigins": [%q],
		"protocol": "openid-connect",
		"standardFlowEnabled": true,
		"attributes": {
			"pkce.code.challenge.method": "S256"
		}
	}`, clientID, clientSecret, redirectURI, webOrigin)

	kc.adminRequest(t, ctx, "POST",
		fmt.Sprintf("/admin/realms/%s/clients", kc.realm),
		token, body)
}

// ---------- Smoke Test ----------

func TestE2E_BrowserInfra_GatewayStarts(t *testing.T) {
	// Verify the browser gateway starts and serves the SPA.
	pki := newTestPKI(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki: pki,
	})

	client := gw.httpClient()

	// Fetch landing page.
	resp, err := client.Get(gw.baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Auth Library Test SPA") {
		t.Error("landing page should contain SPA title")
	}

	// Fetch login page.
	resp2, err := client.Get(gw.baseURL + "/login.html")
	if err != nil {
		t.Fatalf("GET /login.html: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Fatalf("GET /login.html status = %d, want 200", resp2.StatusCode)
	}

	body2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body2), "Password Login") {
		t.Error("login page should contain password login form")
	}
	if !strings.Contains(string(body2), "Login with Keycloak") {
		t.Error("login page should contain OAuth button")
	}
	if !strings.Contains(string(body2), "Magic Link") {
		t.Error("login page should contain magic link form")
	}
}

func TestE2E_BrowserInfra_PasswordLoginFlow(t *testing.T) {
	// Verify password login works through the HTTP gateway.
	pki := newTestPKI(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki: pki,
	})

	// Pre-register a user.
	gw.registerUser(t, "alice@example.com", "StrongPass123!")

	client := gw.httpClient()

	// Login via POST /auth/login.
	loginBody := `{"identifier":"alice@example.com","password":"StrongPass123!"}`
	resp, err := client.Post(
		gw.baseURL+"/auth/login",
		"application/json",
		strings.NewReader(loginBody),
	)
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status = %d, want 200, body = %s", resp.StatusCode, string(body))
	}

	// Check session cookie.
	sessionCookie := findHTTPCookie(resp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no auth_session cookie in login response")
	}
	if sessionCookie.Value == "" {
		t.Error("session cookie value is empty")
	}

	// Verify cookie security attributes.
	if !sessionCookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Error("session cookie must be Secure")
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie SameSite = %v, want Strict", sessionCookie.SameSite)
	}

	// Parse response body.
	var loginResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginResp["subject_id"] != "alice@example.com" {
		t.Errorf("subject_id = %q, want %q", loginResp["subject_id"], "alice@example.com")
	}
}

func TestE2E_BrowserInfra_ProtectedEndpointRequiresAuth(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	// GET /api/me without session cookie → 401.
	resp, err := client.Get(gw.baseURL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("GET /api/me status = %d, want 401", resp.StatusCode)
	}
}

func TestE2E_BrowserInfra_RegisterAndDashboard(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	// Register a new user.
	regBody := `{"identifier":"newuser@example.com","password":"StrongPass123!"}`
	resp, err := client.Post(
		gw.baseURL+"/auth/register",
		"application/json",
		strings.NewReader(regBody),
	)
	if err != nil {
		t.Fatalf("POST /auth/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status = %d, want 201, body = %s", resp.StatusCode, string(body))
	}

	// Extract session cookie and use it to access dashboard.
	sessionCookie := findHTTPCookie(resp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie after registration")
	}

	// GET /api/me with session cookie.
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
	if meData["subject_id"] != "newuser@example.com" {
		t.Errorf("subject_id = %v, want %q", meData["subject_id"], "newuser@example.com")
	}
	// auth_method is empty when fetched via Verify (session-based) since
	// the session store doesn't persist auth_method. The login/register
	// response has auth_method, but Verify-based identity doesn't.
	if sid, ok := meData["session_id"].(string); !ok || sid == "" {
		t.Error("session_id should be non-empty")
	}
}

func TestE2E_BrowserInfra_LogoutClearsSession(t *testing.T) {
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	// Register + login.
	gw.registerUser(t, "logout@example.com", "StrongPass123!")

	client := gw.httpClient()

	loginBody := `{"identifier":"logout@example.com","password":"StrongPass123!"}`
	loginResp, err := client.Post(gw.baseURL+"/auth/login", "application/json", strings.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer loginResp.Body.Close()

	sessionCookie := findHTTPCookie(loginResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// Logout.
	logoutReq, _ := http.NewRequest("POST", gw.baseURL+"/auth/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer logoutResp.Body.Close()

	if logoutResp.StatusCode != 204 {
		t.Fatalf("logout status = %d, want 204", logoutResp.StatusCode)
	}

	// Session cookie should be cleared (MaxAge = -1).
	clearedCookie := findHTTPCookie(logoutResp, "auth_session")
	if clearedCookie == nil {
		t.Fatal("logout should set auth_session cookie to clear it")
	}
	if clearedCookie.MaxAge >= 0 {
		t.Errorf("cleared cookie MaxAge = %d, want < 0", clearedCookie.MaxAge)
	}

	// Using the old session cookie should now fail.
	meReq, _ := http.NewRequest("GET", gw.baseURL+"/api/me", nil)
	meReq.AddCookie(sessionCookie)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /api/me after logout: %v", err)
	}
	defer meResp.Body.Close()

	if meResp.StatusCode != 401 {
		t.Fatalf("GET /api/me after logout status = %d, want 401", meResp.StatusCode)
	}
}

func TestE2E_BrowserInfra_CacheControlHeaders(t *testing.T) {
	// AUTH-0036 AC: pages render correctly, AUTH-0039: no cached authenticated page.
	pki := newTestPKI(t)
	gw := startBrowserGateway(t, browserGatewayConfig{pki: pki})

	client := gw.httpClient()

	for _, path := range []string{"/", "/login.html", "/dashboard.html"} {
		resp, err := client.Get(gw.baseURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()

		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "no-store") {
			t.Errorf("GET %s Cache-Control = %q, want 'no-store'", path, cc)
		}
	}
}

func TestE2E_BrowserInfra_MailHogCaptures(t *testing.T) {
	// Verify MailHog container starts and can receive emails.
	mh := startMailHog(t)

	// Send a test email via SMTP.
	msg := "From: test@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello"
	err := smtp.SendMail(mh.smtpAddr, nil, "test@example.com", []string{"alice@example.com"}, []byte(msg))
	if err != nil {
		t.Fatalf("send email: %v", err)
	}

	// Retrieve from MailHog API.
	email := mh.getLatestMessage(t)
	if !strings.Contains(email.bodyText(), "Hello") {
		t.Errorf("email body = %q, want to contain 'Hello'", email.bodyText())
	}
}

func TestE2E_BrowserInfra_MagicLinkViaMailHog(t *testing.T) {
	// Full magic link flow: request → MailHog captures → extract token → verify.
	pki := newTestPKI(t)
	mh := startMailHog(t)

	gw := startBrowserGateway(t, browserGatewayConfig{
		pki:     pki,
		mailhog: mh,
	})

	// Pre-register a user (magic link requires existing user).
	gw.registerUser(t, "magic@example.com", "unused-password")

	// Clear any prior emails.
	mh.deleteAllMessages(t)

	client := gw.httpClient()

	// Initiate magic link.
	mlBody := `{"identifier":"magic@example.com"}`
	resp, err := client.Post(gw.baseURL+"/auth/magic-link", "application/json", strings.NewReader(mlBody))
	if err != nil {
		t.Fatalf("POST /auth/magic-link: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 {
		t.Fatalf("magic link initiate status = %d, want 202", resp.StatusCode)
	}

	// Fetch email from MailHog.
	email := mh.getLatestMessage(t)
	body := email.bodyText()
	if !strings.Contains(body, "/auth/magic-link/verify?token=") {
		t.Fatalf("email body should contain magic link URL, got: %s", body)
	}

	// Extract the magic link URL.
	magicLinkURL := extractMagicLinkURL(t, body)

	// Visit the magic link to verify.
	verifyResp, err := client.Get(magicLinkURL)
	if err != nil {
		t.Fatalf("GET magic link: %v", err)
	}
	defer verifyResp.Body.Close()

	// Should redirect to dashboard with session cookie set.
	if verifyResp.StatusCode != http.StatusFound {
		t.Fatalf("magic link verify status = %d, want 302", verifyResp.StatusCode)
	}

	loc := verifyResp.Header.Get("Location")
	if loc != "/dashboard.html" {
		t.Errorf("redirect location = %q, want '/dashboard.html'", loc)
	}

	sessionCookie := findHTTPCookie(verifyResp, "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie after magic link verification")
	}

	// Use the session cookie to access /api/me.
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

	var meData map[string]string
	_ = json.NewDecoder(meResp.Body).Decode(&meData)
	if meData["subject_id"] != "magic@example.com" {
		t.Errorf("subject_id = %q, want %q", meData["subject_id"], "magic@example.com")
	}
	// auth_method is not persisted in sessions, so Verify-based identity
	// won't have it. We confirm the magic link flow worked by verifying
	// we got a valid identity (subject_id present) from /api/me.
	if meData["session_id"] == "" {
		t.Error("session_id should be non-empty after magic link login")
	}
}

// ---------- Helpers ----------

// findHTTPCookie finds a cookie by name in a response.
func findHTTPCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// extractMagicLinkURL extracts the magic link URL from an email body.
func extractMagicLinkURL(t *testing.T, body string) string {
	t.Helper()
	// The email body format is: "Click here to log in: https://localhost:PORT/auth/magic-link/verify?token=TOKEN"
	prefix := "Click here to log in: "
	idx := strings.Index(body, prefix)
	if idx == -1 {
		t.Fatalf("magic link URL not found in email body: %s", body)
	}
	urlStr := strings.TrimSpace(body[idx+len(prefix):])
	// URL might have trailing whitespace or newlines.
	if newlineIdx := strings.IndexAny(urlStr, "\r\n"); newlineIdx != -1 {
		urlStr = urlStr[:newlineIdx]
	}
	return urlStr
}
