package ca

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	authority, err := New(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	return authority
}

func TestGenerateAndLoad(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate.
	ca1, err := New(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if ca1.cert == nil || ca1.key == nil {
		t.Fatal("generated CA has nil cert or key")
	}
	if !ca1.cert.IsCA {
		t.Error("generated cert is not a CA")
	}
	if len(ca1.certPEM) == 0 {
		t.Error("certPEM is empty")
	}

	// Load from same files.
	ca2, err := New(certPath, keyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ca1.cert.Equal(ca2.cert) {
		t.Error("loaded cert does not match generated cert")
	}
}

func TestGenerateErrorOnPartialFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate to create both files.
	if _, err := New(certPath, keyPath); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Remove key, keep cert → error.
	dir2 := t.TempDir()
	certPath2 := filepath.Join(dir2, "ca.pem")
	keyPath2 := filepath.Join(dir2, "ca.key")

	// Copy cert only.
	certPEM, _ := readFileBytes(certPath)
	writeFileBytes(certPath2, certPEM)

	_, err := New(certPath2, keyPath2)
	if err == nil {
		t.Fatal("expected error when only cert exists")
	}
}

func TestMintCertificate(t *testing.T) {
	authority := tempCA(t)

	cert, err := authority.MintCertificate("example.com")
	if err != nil {
		t.Fatalf("MintCertificate: %v", err)
	}

	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("leaf is nil")
	}
	if leaf.IsCA {
		t.Error("leaf cert should not be CA")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", leaf.DNSNames)
	}

	// Verify signed by our CA.
	pool := x509.NewCertPool()
	pool.AddCert(authority.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("leaf not signed by CA: %v", err)
	}
}

func TestMintCertificateIP(t *testing.T) {
	authority := tempCA(t)

	cert, err := authority.MintCertificate("127.0.0.1")
	if err != nil {
		t.Fatalf("MintCertificate: %v", err)
	}

	leaf := cert.Leaf
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
}

func TestMintCertificateCache(t *testing.T) {
	authority := tempCA(t)

	cert1, err := authority.MintCertificate("cached.example.com")
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	cert2, err := authority.MintCertificate("cached.example.com")
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}

	if cert1 != cert2 {
		t.Error("cache miss: got different pointers for same host")
	}
}

func TestMintCertificateExpiredCacheEviction(t *testing.T) {
	authority := tempCA(t)

	// Mint a valid cert and cache it.
	cert1, err := authority.MintCertificate("expiry-test.example.com")
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}

	// Manually store a near-expiry cert in the cache.
	expiredCert := &tls.Certificate{
		Certificate: cert1.Certificate,
		PrivateKey:  cert1.PrivateKey,
		Leaf: &x509.Certificate{
			NotAfter: time.Now().Add(30 * time.Minute), // less than 1 hour → should be evicted
		},
	}
	authority.cache.Store("expiry-test.example.com", expiredCert)

	// MintCertificate should regenerate because the cached cert is near-expiry.
	cert2, err := authority.MintCertificate("expiry-test.example.com")
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}

	if cert2 == expiredCert {
		t.Error("expected new cert, got the near-expiry cached cert")
	}
	// New cert should have NotAfter > 1 hour from now.
	if cert2.Leaf == nil {
		t.Fatal("new cert has nil Leaf")
	}
	if time.Until(cert2.Leaf.NotAfter) <= 1*time.Hour {
		t.Errorf("new cert NotAfter too soon: %v", cert2.Leaf.NotAfter)
	}
}

func TestMintCertificateTLSHandshake(t *testing.T) {
	authority := tempCA(t)

	// Start a TLS listener using the CA's dynamic config.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", authority.TLSConfigForClient())
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Accept one connection in background, complete TLS handshake.
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		// Force TLS handshake to complete server-side before closing.
		if tlsConn, ok := conn.(*tls.Conn); ok {
			done <- tlsConn.Handshake()
			return
		}
		done <- nil
	}()

	// Build a client that trusts our CA.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("failed to add CA cert to pool")
	}

	addr := ln.Addr().String()

	// Use "localhost" as SNI — IP addresses don't work with TLS SNI.
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	conn.Close()

	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// helpers for TestGenerateErrorOnPartialFiles
func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func writeFileBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
