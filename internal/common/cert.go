// Package common holds code shared between the pivot server and the pivot
// agent: certificate generation/pinning and the wire protocol used on the
// control stream.
package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// GenerateSelfSigned creates (or loads, if both files already exist) an
// ECDSA P-256 self-signed certificate for the server and returns the TLS
// certificate plus the SHA-256 fingerprint of the leaf certificate (used for
// pinning instead of trusting a CA, since there usually is no CA in an
// engagement/exam network).
func GenerateSelfSigned(certPath, keyPath string, hosts []string) (tls.Certificate, string, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("loading existing cert: %w", err)
		}
		fp, err := fingerprintFromCertFile(certPath)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		return cert, fp, nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"pivot"}, CommonName: "pivot-server"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(20 * 365 * 24 * time.Hour), // long-lived: exams/engagements shouldn't die mid-run
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	// Always valid for loopback/any-host dialing in the lab.
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("0.0.0.0"), net.ParseIP("127.0.0.1"))

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, "", err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	sum := sha256.Sum256(der)
	return cert, hex.EncodeToString(sum[:]), nil
}

func fingerprintFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("invalid PEM cert")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// PinnedVerifier builds a tls.Config.VerifyPeerCertificate callback (plus
// InsecureSkipVerify=true, since we are deliberately bypassing normal CA
// chain validation in favor of certificate pinning) that accepts the
// connection only if the leaf certificate's SHA-256 fingerprint matches
// expectedFingerprint exactly. This is what lets the agent trust a
// self-signed cert over a hostile/unknown network without either disabling
// verification outright or requiring a real CA.
func PinnedVerifier(expectedFingerprint string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificate presented")
		}
		sum := sha256.Sum256(rawCerts[0])
		got := hex.EncodeToString(sum[:])
		if got != expectedFingerprint {
			return fmt.Errorf("certificate fingerprint mismatch: got %s, expected %s (server may have been replaced/MITM'd, or you copied the pin wrong)", got, expectedFingerprint)
		}
		return nil
	}
}
