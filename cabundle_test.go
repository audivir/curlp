package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func testCert(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "curlp test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestReadCertificatesNeverTakesPrivateKeys(t *testing.T) {
	dir := t.TempDir()
	cert := testCert(t, 1)
	combined := slicesConcat(cert, testPrivateKey(t), cert, []byte("-----BEGIN CERTIFICATE-----\nbm9wZQ==\n-----END CERTIFICATE-----\n"))
	writeFile(t, filepath.Join(dir, "combined.pem"), string(combined))

	got, err := readCertificates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], cert) {
		t.Fatalf("got %d certificates, want only the one valid, deduplicated certificate", len(got))
	}
}

func TestReadCertificatesFollowsSymlinkedRootAndFiltersSuffixes(t *testing.T) {
	real := t.TempDir()
	a, b := testCert(t, 1), testCert(t, 2)
	writeFile(t, filepath.Join(real, "a.PEM"), string(a))
	writeFile(t, filepath.Join(real, "nested", "b.crt"), string(b))
	writeFile(t, filepath.Join(real, "ignored.key"), string(testCert(t, 3)))
	writeFile(t, filepath.Join(real, "ignored.txt"), string(testCert(t, 4)))

	link := filepath.Join(t.TempDir(), "ssl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := readCertificates(link)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, [][]byte{a, b}) {
		t.Errorf("got %d certificates, want a.PEM and nested/b.crt only", len(got))
	}
}

func TestReadCertificatesMissingPath(t *testing.T) {
	got, err := readCertificates(filepath.Join(t.TempDir(), "missing"))
	if err != nil || got != nil {
		t.Errorf("got %v, %v, want no certificates and no error", got, err)
	}
}

func TestHasOwnTLSTrust(t *testing.T) {
	for _, args := range [][]string{
		{"--cacert", "x.pem", "https://h"},
		{"--cacert=x.pem"},
		{"--capath", "d"},
		{"-k"},
		{"-sk"},
		{"--insecure"},
	} {
		if !hasOwnTLSTrust(args) {
			t.Errorf("%v must count as own trust", args)
		}
	}
	for _, args := range [][]string{{"-s", "https://h"}, {"-H", "k: v"}, {"--key", "k.pem"}} {
		if hasOwnTLSTrust(args) {
			t.Errorf("%v must not count as own trust", args)
		}
	}
}

func TestCABundleArgs(t *testing.T) {
	caDir, bundlePath := t.TempDir(), filepath.Join(t.TempDir(), "cache", "ca-bundle.pem")
	cert := testCert(t, 1)

	if got, err := caBundleArgs([]string{"https://h"}, caDir, bundlePath); err != nil || got != nil {
		t.Fatalf("no certificates: got %v, %v, want nil", got, err)
	}
	if _, err := os.Stat(bundlePath); err == nil {
		t.Fatal("no bundle may be written without certificates")
	}

	writeFile(t, filepath.Join(caDir, "ca.pem"), string(cert))
	if got, err := caBundleArgs([]string{"-k", "https://h"}, caDir, bundlePath); err != nil || got != nil {
		t.Fatalf("own trust: got %v, %v, want nil", got, err)
	}

	got, err := caBundleArgs([]string{"https://h"}, caDir, bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"--cacert", bundlePath}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, cert) {
		t.Error("the certificate must follow the standard roots")
	}
	if n := bytes.Count(data, []byte("BEGIN CERTIFICATE")); n < 100 {
		t.Errorf("the bundle has only %d certificates, the standard roots are missing", n)
	}
}

func TestWriteIfChangedKeepsIdenticalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := writeIfChanged(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeIfChanged(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Error("identical content must not replace the file")
	}
	if err := writeIfChanged(path, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "two" {
		t.Errorf("got %q after a change", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files were left behind: %d entries", len(entries))
	}
}

func slicesConcat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
