// Package ca provides a certificate authority for MITM TLS interception.
// It generates ECDSA P-256 CA and leaf certificates on the fly.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CA holds the root certificate and key used to sign per-host leaf certificates.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	cache   sync.Map // hostname → *tls.Certificate
}

// New loads a CA from certPath and keyPath. If neither file exists, it generates
// a new CA and writes the files. Returns an error if only one file exists.
func New(certPath, keyPath string) (*CA, error) {
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	switch {
	case certExists && keyExists:
		return load(certPath, keyPath)
	case !certExists && !keyExists:
		return generate(certPath, keyPath)
	default:
		return nil, fmt.Errorf("ca: both %s and %s must exist, or neither", certPath, keyPath)
	}
}

// CertPEM returns the PEM-encoded CA certificate, suitable for adding to a
// client trust pool.
func (c *CA) CertPEM() []byte {
	return c.certPEM
}

// MintCertificate returns a TLS certificate for the given host, signed by the CA.
// Results are cached so repeated calls for the same host return the same cert.
// Expired or near-expiry cached certs are regenerated automatically.
func (c *CA) MintCertificate(host string) (*tls.Certificate, error) {
	if cached, ok := c.cache.Load(host); ok {
		tlsCert := cached.(*tls.Certificate)
		if tlsCert.Leaf != nil && time.Until(tlsCert.Leaf.NotAfter) > 1*time.Hour {
			return tlsCert, nil
		}
		c.cache.Delete(host)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}

	actual, _ := c.cache.LoadOrStore(host, tlsCert)
	return actual.(*tls.Certificate), nil
}

// TLSConfigForClient returns a tls.Config that dynamically mints certificates
// for each connecting client based on the SNI or requested host.
func (c *CA) TLSConfigForClient() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.MintCertificate(hello.ServerName)
		},
	}
}

func generate(certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mindgame CA"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write cert file.
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("ca: write cert: %w", err)
	}

	// Write key file.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("ca: write key: %w", err)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

func load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ca: read cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca: read key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca: no PEM block in %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca: no PEM block in %s", keyPath)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse key: %w", err)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
