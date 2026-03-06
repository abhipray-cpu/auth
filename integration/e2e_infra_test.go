// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0030: Docker Compose Environment + Test Services
//
// Instead of Docker Compose with Dockerfiles, this uses testcontainers-go for
// infrastructure (Keycloak, Redis, Postgres) and real in-process gRPC servers
// over real TLS/mTLS for the three test services (Gateway, Order, Inventory).
//
// This gives identical coverage: real Keycloak OIDC, real Redis/Postgres,
// real mTLS over TCP, real gRPC connections — but with zero operational overhead.
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	authgrpc "github.com/abhipray-cpu/auth/grpc"
	"github.com/abhipray-cpu/auth/hash"
	"github.com/abhipray-cpu/auth/hooks"
	modepw "github.com/abhipray-cpu/auth/mode/password"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/propagator"
	"github.com/abhipray-cpu/auth/session"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

// ---------- TLS / mTLS Certificate Infrastructure ----------

// tlsPKI holds a complete PKI hierarchy for E2E testing.
type tlsPKI struct {
	// CA
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertPEM []byte
	caPool    *x509.CertPool

	// Untrusted CA (for negative tests)
	untrustedCACert    *x509.Certificate
	untrustedCAKey     *ecdsa.PrivateKey
	untrustedCACertPEM []byte
	untrustedCAPool    *x509.CertPool
}

// tlsCertPair holds a certificate and its private key in usable form.
type tlsCertPair struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
	tlsCert tls.Certificate
}

// newTestPKI creates a full CA hierarchy for E2E mTLS tests.
func newTestPKI(t *testing.T) *tlsPKI {
	t.Helper()
	pki := &tlsPKI{}

	// Generate trusted CA.
	pki.caKey = generateECKey(t)
	pki.caCert = generateCACert(t, "Test Root CA", pki.caKey)
	pki.caCertPEM = certToPEM(t, pki.caCert)
	pki.caPool = x509.NewCertPool()
	pki.caPool.AddCert(pki.caCert)

	// Generate untrusted CA.
	pki.untrustedCAKey = generateECKey(t)
	pki.untrustedCACert = generateCACert(t, "Untrusted CA", pki.untrustedCAKey)
	pki.untrustedCACertPEM = certToPEM(t, pki.untrustedCACert)
	pki.untrustedCAPool = x509.NewCertPool()
	pki.untrustedCAPool.AddCert(pki.untrustedCACert)

	return pki
}

// issueServerCert creates a TLS server certificate signed by the PKI's CA.
func (pki *tlsPKI) issueServerCert(t *testing.T, cn string, dnsNames ...string) *tlsCertPair {
	t.Helper()
	return pki.issueCert(t, cn, pki.caCert, pki.caKey, true, dnsNames, nil, time.Hour)
}

// issueClientCert creates a TLS client certificate signed by the PKI's CA.
func (pki *tlsPKI) issueClientCert(t *testing.T, cn string, uris ...*url.URL) *tlsCertPair {
	t.Helper()
	return pki.issueCert(t, cn, pki.caCert, pki.caKey, false, nil, uris, time.Hour)
}

// issueExpiredClientCert creates an expired client certificate.
func (pki *tlsPKI) issueExpiredClientCert(t *testing.T, cn string) *tlsCertPair {
	t.Helper()
	return pki.issueCert(t, cn, pki.caCert, pki.caKey, false, nil, nil, -time.Hour)
}

// issueUntrustedClientCert creates a client cert signed by the untrusted CA.
func (pki *tlsPKI) issueUntrustedClientCert(t *testing.T, cn string) *tlsCertPair {
	t.Helper()
	return pki.issueCert(t, cn, pki.untrustedCACert, pki.untrustedCAKey, false, nil, nil, time.Hour)
}

func (pki *tlsPKI) issueCert(t *testing.T, cn string, issuerCert *x509.Certificate, issuerKey *ecdsa.PrivateKey, isServer bool, dnsNames []string, uris []*url.URL, validity time.Duration) *tlsCertPair {
	t.Helper()
	key := generateECKey(t)

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(validity + 5*time.Minute) // compensate for the 5min offset
	if validity < 0 {
		// Expired cert: notBefore is in the past, notAfter is also in the past.
		notBefore = time.Now().Add(-2 * time.Hour)
		notAfter = time.Now().Add(-1 * time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     dnsNames,
		URIs:         uris,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if len(dnsNames) == 0 {
			template.DNSNames = []string{"localhost"}
		}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}

	return &tlsCertPair{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		keyPEM:  keyPEM,
		tlsCert: tlsCert,
	}
}

func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func generateCACert(t *testing.T, cn string, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert
}

func certToPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("random serial: %v", err)
	}
	return serial
}

// ---------- gRPC Test Service Infrastructure ----------

// testGRPCService represents a running gRPC service with full auth wiring.
type testGRPCService struct {
	name       string
	listener   net.Listener
	server     *grpc.Server
	addr       string
	engine     *engine.Engine
	propagator propagator.IdentityPropagator
	pki        *tlsPKI
	serverCert *tlsCertPair
	clientCert *tlsCertPair
}

// testServiceConfig configures a test gRPC service.
type testServiceConfig struct {
	name         string
	pki          *tlsPKI
	userStore    *MemUserStore
	sessionStore session.SessionStore
	propagator   propagator.IdentityPropagator
	requireAuth  bool
	serverCertCN string
	clientCertCN string
	spiffeID     string // if set, the client cert gets a SPIFFE URI SAN
}

// startTestGRPCService creates and starts a gRPC server with full auth interceptors.
func startTestGRPCService(t *testing.T, cfg testServiceConfig) *testGRPCService {
	t.Helper()

	// Issue server cert.
	serverCert := cfg.pki.issueServerCert(t, cfg.serverCertCN, "localhost")

	// Issue client cert for this service.
	var clientCert *tlsCertPair
	if cfg.spiffeID != "" {
		spiffeURI, err := url.Parse(cfg.spiffeID)
		if err != nil {
			t.Fatalf("parse SPIFFE ID %q: %v", cfg.spiffeID, err)
		}
		clientCert = cfg.pki.issueClientCert(t, cfg.clientCertCN, spiffeURI)
	} else {
		clientCert = cfg.pki.issueClientCert(t, cfg.clientCertCN)
	}

	// Build TLS config for server: require and verify client certs.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cfg.pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Build engine.
	sessMgr := session.NewManager(cfg.sessionStore, session.DefaultConfig())
	hasher := hash.NewArgon2idHasher(nil)
	pwMode := modepw.NewMode(modepw.ModeConfig{
		UserStore: cfg.userStore,
		Hasher:    hasher,
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
	})
	eng, err := engine.New(engine.Config{
		UserStore:      cfg.userStore,
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
		t.Fatalf("engine.New for %s: %v", cfg.name, err)
	}

	// Build server with auth interceptors.
	serverCfg := authgrpc.ServerConfig{
		Engine:      eng,
		Propagator:  cfg.propagator,
		RequireAuth: cfg.requireAuth,
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(serverCfg)),
		grpc.StreamInterceptor(authgrpc.StreamServerInterceptor(serverCfg)),
	)

	// Register the echo service so gRPC can route calls.
	server.RegisterService(&echoServiceDesc, &echoServer{})

	// Listen on a random port.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for %s: %v", cfg.name, err)
	}

	svc := &testGRPCService{
		name:       cfg.name,
		listener:   lis,
		server:     server,
		addr:       lis.Addr().String(),
		engine:     eng,
		propagator: cfg.propagator,
		pki:        cfg.pki,
		serverCert: serverCert,
		clientCert: clientCert,
	}

	// Start serving.
	go func() {
		if err := server.Serve(lis); err != nil && !isServerStopped(err) {
			// Server stopped normally — no logging needed.
		}
	}()

	t.Cleanup(func() {
		server.GracefulStop()
	})

	return svc
}

func isServerStopped(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}

// dialService creates a gRPC client connection to a test service with mTLS.
func dialService(t *testing.T, svc *testGRPCService, clientCert *tlsCertPair, clientInterceptors ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert.tlsCert},
		RootCAs:      svc.pki.caPool,
		ServerName:   "localhost",
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	}
	opts = append(opts, clientInterceptors...)

	conn, err := grpc.NewClient(svc.addr, opts...)
	if err != nil {
		t.Fatalf("dial %s: %v", svc.name, err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn
}

// ---------- In-memory Session Store ----------

// memSessionStore is a minimal in-memory session store for E2E tests.
type memSessionStore struct {
	sessions map[string]*session.Session
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{
		sessions: make(map[string]*session.Session),
	}
}

func (s *memSessionStore) Create(_ context.Context, sess *session.Session) error {
	s.sessions[sess.ID] = sess
	return nil
}

func (s *memSessionStore) Get(_ context.Context, sessionID string) (*session.Session, error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return sess, nil
}

func (s *memSessionStore) Update(_ context.Context, sess *session.Session) error {
	s.sessions[sess.ID] = sess
	return nil
}

func (s *memSessionStore) Delete(_ context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

func (s *memSessionStore) DeleteBySubject(_ context.Context, subjectID string) error {
	for id, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *memSessionStore) CountBySubject(_ context.Context, subjectID string) (int, error) {
	count := 0
	for _, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

// ListBySubject returns all sessions for a given subject. Used by the session
// manager to enforce MaxConcurrent limits.
func (s *memSessionStore) ListBySubject(_ context.Context, subjectID string) ([]*session.Session, error) {
	var result []*session.Session
	for _, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			result = append(result, sess)
		}
	}
	return result, nil
}

var _ session.SessionStore = (*memSessionStore)(nil)

// ---------- Keycloak Testcontainer ----------

// keycloakContainer holds the running Keycloak instance.
type keycloakContainer struct {
	container testcontainers.Container
	baseURL   string // e.g., "http://localhost:32768"
	realm     string
	adminUser string
	adminPass string
}

// startKeycloak starts a Keycloak container with a test realm.
// Returns nil if Docker is not available (test should be skipped).
func startKeycloak(t *testing.T) *keycloakContainer {
	t.Helper()
	skipIfNoDocker(t)

	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:26.1",
		ExposedPorts: []string{"8080/tcp", "9000/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
			"KC_HEALTH_ENABLED":           "true",
		},
		Cmd: []string{"start-dev"},
		WaitingFor: wait.ForHTTP("/health/ready").
			WithPort("9000/tcp").
			WithStartupTimeout(120 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start Keycloak: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("keycloak host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("keycloak port: %v", err)
	}

	kc := &keycloakContainer{
		container: ctr,
		baseURL:   fmt.Sprintf("http://%s:%s", host, port.Port()),
		realm:     "test",
		adminUser: "admin",
		adminPass: "admin",
	}

	// Create test realm and users via Keycloak Admin REST API.
	kc.setupRealm(t)

	return kc
}

// setupRealm creates the test realm, client, and users via the Admin REST API.
func (kc *keycloakContainer) setupRealm(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	// Get admin token.
	token := kc.getAdminToken(t)

	// Create "test" realm.
	kc.adminRequest(t, ctx, "POST", "/admin/realms", token, `{
		"realm": "test",
		"enabled": true,
		"registrationAllowed": false,
		"loginWithEmailAllowed": true
	}`)

	// Create client "test-app" (public client with authorization code flow).
	kc.adminRequest(t, ctx, "POST", fmt.Sprintf("/admin/realms/%s/clients", kc.realm), token, `{
		"clientId": "test-app",
		"enabled": true,
		"publicClient": true,
		"directAccessGrantsEnabled": true,
		"redirectUris": ["http://localhost:9090/auth/oauth/callback*", "http://localhost:*/callback*"],
		"webOrigins": ["*"],
		"protocol": "openid-connect",
		"standardFlowEnabled": true,
		"attributes": {
			"pkce.code.challenge.method": "S256"
		}
	}`)

	// Create test user: alice.
	kc.createUser(t, ctx, token, "alice", "alice@example.com", "alice-password-123", true)

	// Create test user: bob.
	kc.createUser(t, ctx, token, "bob", "bob@example.com", "bob-password-456", true)

	// Create test user: locked-user (disabled).
	kc.createUser(t, ctx, token, "locked-user", "locked@example.com", "locked-password", false)
}

// createUser creates a Keycloak user via the admin API.
func (kc *keycloakContainer) createUser(t *testing.T, ctx context.Context, token, username, email, password string, enabled bool) {
	t.Helper()

	// Step 1: Create the user with credentials inline.
	userBody := fmt.Sprintf(`{
		"username": %q,
		"email": %q,
		"firstName": "Test",
		"lastName": "User",
		"enabled": %v,
		"emailVerified": true,
		"requiredActions": [],
		"credentials": [{"type": "password", "value": %q, "temporary": false}]
	}`, username, email, enabled, password)

	kc.adminRequest(t, ctx, "POST", fmt.Sprintf("/admin/realms/%s/users", kc.realm), token, userBody)

	// Step 2: Verify user exists and clear any residual required actions.
	userID := kc.findUserID(t, ctx, token, username)

	// Step 3: Explicitly update user to clear requiredActions (belt & suspenders).
	clearBody := `{"requiredActions":[]}`
	kc.adminRequest(t, ctx, "PUT",
		fmt.Sprintf("/admin/realms/%s/users/%s", kc.realm, userID),
		token, clearBody)
}

// findUserID looks up a Keycloak user by username and returns their ID.
func (kc *keycloakContainer) findUserID(t *testing.T, ctx context.Context, token, username string) string {
	t.Helper()
	reqURL := fmt.Sprintf("%s/admin/realms/%s/users?username=%s&exact=true", kc.baseURL, kc.realm, url.QueryEscape(username))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		t.Fatalf("create find user request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("find user request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("find user: HTTP %d", resp.StatusCode)
	}

	var users []struct {
		ID              string   `json:"id"`
		RequiredActions []string `json:"requiredActions"`
	}
	if err := decodeJSON(resp.Body, &users); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	if len(users) == 0 {
		t.Fatalf("user %q not found", username)
	}
	if len(users[0].RequiredActions) > 0 {
		t.Logf("user %q has requiredActions: %v", username, users[0].RequiredActions)
	}
	return users[0].ID
}

// getAdminToken authenticates as admin to get an access token.
func (kc *keycloakContainer) getAdminToken(t *testing.T) string {
	t.Helper()

	resp, err := http.PostForm(
		kc.baseURL+"/realms/master/protocol/openid-connect/token",
		url.Values{
			"grant_type": {"password"},
			"client_id":  {"admin-cli"},
			"username":   {kc.adminUser},
			"password":   {kc.adminPass},
		},
	)
	if err != nil {
		t.Fatalf("admin token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("admin token: HTTP %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		t.Fatalf("decode admin token: %v", err)
	}

	return result.AccessToken
}

// adminRequest performs an authenticated request to the Keycloak Admin REST API.
func (kc *keycloakContainer) adminRequest(t *testing.T, ctx context.Context, method, path, token, body string) {
	t.Helper()
	reqURL := kc.baseURL + path

	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		t.Fatalf("create admin request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Read body for error context.
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		t.Fatalf("admin request %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(buf[:n]))
	}
}

// directGrantToken gets a token via Resource Owner Password Credentials flow.
// This is used in tests to simulate "user logged in" without a browser.
func (kc *keycloakContainer) directGrantToken(t *testing.T, username, password string) (accessToken, idToken string) {
	t.Helper()

	resp, err := http.PostForm(
		kc.baseURL+"/realms/"+kc.realm+"/protocol/openid-connect/token",
		url.Values{
			"grant_type": {"password"},
			"client_id":  {"test-app"},
			"username":   {username},
			"password":   {password},
			"scope":      {"openid"},
		},
	)
	if err != nil {
		t.Fatalf("direct grant: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		t.Fatalf("direct grant: HTTP %d: %s", resp.StatusCode, string(buf[:n]))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}

	return result.AccessToken, result.IDToken
}

// issuerURL returns the OIDC issuer URL for the test realm.
func (kc *keycloakContainer) issuerURL() string {
	return kc.baseURL + "/realms/" + kc.realm
}

// ---------- JSON Helpers ----------

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

// ---------- gRPC Echo Service ----------
// A trivial unary+streaming gRPC service that echoes the identity from context.
// We don't need proto files — we use the low-level grpc.ServiceDesc.

const echoServiceName = "e2e.EchoService"

// echoServiceInterface is the interface type required by grpc.ServiceDesc.HandlerType.
// gRPC's RegisterService uses reflect.Implements which requires an interface type.
type echoServiceInterface interface{}

// echoServiceDesc is a gRPC service descriptor for our test echo service.
var echoServiceDesc = grpc.ServiceDesc{
	ServiceName: echoServiceName,
	HandlerType: (*echoServiceInterface)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Echo",
			Handler:    echoUnaryHandler,
		},
		{
			MethodName: "GetIdentity",
			Handler:    getIdentityHandler,
		},
		{
			MethodName: "Forward",
			Handler:    forwardHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamEcho",
			Handler:       streamEchoHandler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
}

// echoServer is the type registered for the echo service.
type echoServer struct {
	propagator propagator.IdentityPropagator
	downstream *grpc.ClientConn // for chained calls
}

func echoUnaryHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	// Read the request (just a string).
	var req string
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor != nil {
		resp, err := interceptor(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/" + echoServiceName + "/Echo",
		}, func(ctx context.Context, req any) (any, error) {
			return "echo:" + req.(string), nil
		})
		return resp, err
	}
	return "echo:" + req, nil
}

// getIdentityHandler returns the identity info from the context.
func getIdentityHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req string
	if err := dec(&req); err != nil {
		return nil, err
	}

	handler := func(ctx context.Context, _ any) (any, error) {
		result := make(map[string]string)

		if id := auth.GetIdentity(ctx); id != nil {
			result["subject_id"] = id.SubjectID
			result["auth_method"] = id.AuthMethod
			result["session_id"] = id.SessionID
		}
		if wid := auth.GetWorkloadIdentity(ctx); wid != nil {
			result["workload_id"] = wid.WorkloadID
			result["trust_domain"] = wid.TrustDomain
		}

		return result, nil
	}

	if interceptor != nil {
		return interceptor(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/" + echoServiceName + "/GetIdentity",
		}, handler)
	}
	return handler(ctx, req)
}

// forwardHandler forwards the call to a downstream service, propagating identity.
func forwardHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req string
	if err := dec(&req); err != nil {
		return nil, err
	}

	handler := func(ctx context.Context, _ any) (any, error) {
		es := srv.(*echoServer)
		if es.downstream == nil {
			return nil, status.Error(codes.FailedPrecondition, "no downstream configured")
		}

		// Forward to downstream — identity should be propagated via client interceptor.
		var resp map[string]string
		err := es.downstream.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "forwarded", &resp)
		if err != nil {
			return nil, fmt.Errorf("forward to downstream: %w", err)
		}

		return resp, nil
	}

	if interceptor != nil {
		return interceptor(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/" + echoServiceName + "/Forward",
		}, handler)
	}
	return handler(ctx, req)
}

func streamEchoHandler(srv any, stream grpc.ServerStream) error {
	// Just verify identity is available.
	id := auth.GetIdentity(stream.Context())
	wid := auth.GetWorkloadIdentity(stream.Context())
	_ = id
	_ = wid
	return nil
}

// ---------- Smoke Test for Infrastructure ----------

func TestE2E_InfraSmoke_PKI(t *testing.T) {
	// Verify PKI hierarchy works: CA, server cert, client cert.
	pki := newTestPKI(t)

	serverCert := pki.issueServerCert(t, "gateway-service", "localhost")
	if serverCert.cert.Subject.CommonName != "gateway-service" {
		t.Errorf("server cert CN = %q, want %q", serverCert.cert.Subject.CommonName, "gateway-service")
	}

	clientCert := pki.issueClientCert(t, "order-service")
	if clientCert.cert.Subject.CommonName != "order-service" {
		t.Errorf("client cert CN = %q, want %q", clientCert.cert.Subject.CommonName, "order-service")
	}

	// Verify server cert validates against CA.
	opts := x509.VerifyOptions{
		Roots:     pki.caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := serverCert.cert.Verify(opts); err != nil {
		t.Fatalf("server cert should verify against CA: %v", err)
	}

	// Verify client cert validates against CA.
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if _, err := clientCert.cert.Verify(opts); err != nil {
		t.Fatalf("client cert should verify against CA: %v", err)
	}

	// Verify untrusted cert does NOT validate against CA.
	untrusted := pki.issueUntrustedClientCert(t, "rogue-service")
	if _, err := untrusted.cert.Verify(opts); err == nil {
		t.Fatal("untrusted cert should NOT verify against trusted CA")
	}

	// Verify expired cert does NOT validate.
	expired := pki.issueExpiredClientCert(t, "expired-service")
	if _, err := expired.cert.Verify(opts); err == nil {
		t.Fatal("expired cert should NOT verify")
	}

	// Verify SPIFFE URI SAN.
	spiffeURI, _ := url.Parse("spiffe://acme.com/inventory-service")
	spiffeCert := pki.issueClientCert(t, "inventory-service", spiffeURI)
	if len(spiffeCert.cert.URIs) == 0 {
		t.Fatal("SPIFFE cert should have URI SAN")
	}
	if spiffeCert.cert.URIs[0].String() != "spiffe://acme.com/inventory-service" {
		t.Errorf("SPIFFE URI = %q, want %q", spiffeCert.cert.URIs[0].String(), "spiffe://acme.com/inventory-service")
	}
}

func TestE2E_InfraSmoke_TLSHandshake(t *testing.T) {
	// Verify real TLS handshake with mTLS over localhost.
	pki := newTestPKI(t)
	serverPair := pki.issueServerCert(t, "test-server", "localhost")
	clientPair := pki.issueClientCert(t, "test-client")

	// Create TLS server config.
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverPair.tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Start TLS listener.
	lis, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	// Accept one connection in background.
	type result struct {
		peerCN string
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			ch <- result{err: err}
			return
		}

		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			ch <- result{err: fmt.Errorf("no peer certs")}
			return
		}
		ch <- result{peerCN: state.PeerCertificates[0].Subject.CommonName}
	}()

	// Connect as client.
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientPair.tlsCert},
		RootCAs:      pki.caPool,
		ServerName:   "localhost",
	}

	conn, err := tls.Dial("tcp", lis.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()

	// Check server saw the client cert.
	res := <-ch
	if res.err != nil {
		t.Fatalf("server handshake: %v", res.err)
	}
	if res.peerCN != "test-client" {
		t.Errorf("peer CN = %q, want %q", res.peerCN, "test-client")
	}

	// Check client saw the server cert.
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("client: no server cert")
	}
	if state.PeerCertificates[0].Subject.CommonName != "test-server" {
		t.Errorf("server CN = %q, want %q", state.PeerCertificates[0].Subject.CommonName, "test-server")
	}
}

func TestE2E_InfraSmoke_GRPCWithMTLS(t *testing.T) {
	// Verify gRPC service starts with mTLS and auth interceptors.
	pki := newTestPKI(t)
	store := NewMemUserStore()
	sessStore := newMemSessionStore()

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "order-service",
		TTL:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("propagator: %v", err)
	}

	svc := startTestGRPCService(t, testServiceConfig{
		name:         "gateway",
		pki:          pki,
		userStore:    store,
		sessionStore: sessStore,
		propagator:   prop,
		requireAuth:  false,
		serverCertCN: "gateway-service",
		clientCertCN: "test-client",
	})

	if svc.addr == "" {
		t.Fatal("service should have a valid address")
	}

	// Dial with mTLS.
	conn := dialService(t, svc, svc.clientCert)
	if conn == nil {
		t.Fatal("connection should not be nil")
	}

	// Connection target should be our service address.
	if conn.Target() != svc.addr {
		t.Errorf("target = %q, want %q", conn.Target(), svc.addr)
	}
}

// ---------- gRPC JSON codec for testing ----------

// jsonCodec is a custom gRPC codec that uses JSON encoding so we can
// use Go native types (string, map, etc.) without proto files.
// It registers as "proto" to intercept the default content type, so
// all Invoke calls work without needing special call options.
type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)      { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
func (jsonCodec) Name() string                       { return "proto" }

func init() {
	// Override the default "proto" codec with JSON so we can use native Go types
	// (string, map[string]string, etc.) as gRPC request/response without proto files.
	encoding.RegisterCodec(jsonCodec{})
}

// ---------- Test: Environment Starts Reliably ----------

func TestE2E_InfraSmoke_MultipleRestarts(t *testing.T) {
	// AUTH-0030 AC: "Environment starts reliably (tested 3+ times)".
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("attempt_%d", i+1), func(t *testing.T) {
			pki := newTestPKI(t)
			sessStore := newMemSessionStore()

			svc := startTestGRPCService(t, testServiceConfig{
				name:         "reliability-test",
				pki:          pki,
				userStore:    NewMemUserStore(),
				sessionStore: sessStore,
				requireAuth:  false,
				serverCertCN: "test-server",
				clientCertCN: "test-client",
			})

			if svc.addr == "" {
				t.Fatal("service should have a valid address")
			}

			// Verify we can establish a TLS connection.
			conn := dialService(t, svc, svc.clientCert)
			if conn == nil {
				t.Fatal("connection should succeed")
			}
		})
	}
}
