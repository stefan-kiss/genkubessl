/*
 * Copyright (c) 2019. Stefan Kiss.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package sslutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	// PrivateKeyBlockType is a possible value for pem.Block.Type.
	PrivateKeyBlockType = "PRIVATE KEY"
	// PublicKeyBlockType is a possible value for pem.Block.Type.
	PublicKeyBlockType = "PUBLIC KEY"
	// CertificateBlockType is a possible value for pem.Block.Type.
	CertificateBlockType = "CERTIFICATE"
	// RSAPrivateKeyBlockType is a possible value for pem.Block.Type.
	RSAPrivateKeyBlockType = "RSA PRIVATE KEY"
	// ECPrivateKeyBlockType is a possible value for pem.Block.Type.
	ECPrivateKeyBlockType = "EC PRIVATE KEY"

	rsaKeySize = 2048

	duration1d   = time.Hour * 24
	duration365d = time.Hour * 24 * 365
)

// CertConf contains the basic fields required for creating a certificate
type CertConf struct {
	// Validity in days
	Validity           int      `json:"Validity"`
	KeySize            int      `json:"KeySize"`
	CommonName         string   `json:"CommonName"`
	Organization       []string `json:"Organization"`
	OrganizationalUnit []string `json:"OrganizationalUnit"`
	Country            []string `json:"Country"`
	Locality           []string `json:"Locality"`
	Province           []string `json:"Province"`
	StreetAddress      []string `json:"StreetAddress"`
	PostalCode         []string `json:"PostalCode"`
	AltNames           AltNames `json:"AltNames"`
	Usages             []x509.ExtKeyUsage
}

// AltNames contains the domain names and IP addresses that will be added
// to the API Server's x509 certificate SubAltNames field. The values will
// be passed directly to the x509.Certificate object.
type AltNames struct {
	DNSNames []string `json:"DNSNames"`
	IPs      []net.IP `json:"IPs"`
}

func NewCAConfig(validity int, commonname string, organization []string, altnames []string) *CertConf {

	template := CertConf{
		Validity:     validity,
		CommonName:   commonname,
		Organization: organization,
	}

	if ip := net.ParseIP(commonname); ip != nil {
		template.AltNames.IPs = append(template.AltNames.IPs, ip)
	} else {
		template.AltNames.DNSNames = append(template.AltNames.DNSNames, commonname)
	}

	netips := make([]net.IP, 0)
	dnsnames := make([]string, 0)

	for _, name := range altnames {
		if netip := net.ParseIP(name); netip != nil {
			netips = append(netips, netip)
		} else {
			dnsnames = append(dnsnames, name)
		}
	}

	template.AltNames.IPs = append(template.AltNames.IPs, netips...)
	template.AltNames.DNSNames = append(template.AltNames.DNSNames, dnsnames...)

	return &template
}

func ipsToStrings(ips []net.IP) []string {
	ss := make([]string, 0, len(ips))
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	return ss
}

// NewSelfSignedCACert creates a CA certificate
func NewSelfSignedCACert(cfg CertConf, caKey interface{}) (*x509.Certificate, interface{}, error) {
	var err error
	if caKey == nil {
		caKey, err = NewPrivateKey("")
		if err != nil {
			return nil, nil, err
		}
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(duration365d * 10).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, publicKey(caKey), caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDERBytes)
	return cert, caKey, err
}

func NewPrivateKey(keytype string) (interface{}, error) {
	var rsaBits int = rsaKeySize
	var priv interface{}
	var err error
	switch keytype {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		fmt.Printf("Unrecognized elliptic curve: %s", keytype)
		return nil, nil
	}
	if err != nil {
		fmt.Printf("failed to generate private key: %s", err)
		return nil, nil
	}
	return priv, err
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func GenerateSelfSignedCertKey(cfg CertConf, caCertificate *x509.Certificate, caKey, certKey interface{}) (*x509.Certificate, interface{}, error) {
	validFrom := time.Now().Add(-time.Hour) // valid an hour earlier to avoid flakes due to clock skew
	maxAge := time.Hour * 24 * 365          // one year self-signed certs

	var err error
	if certKey == nil {
		certKey, err = NewPrivateKey("")
		if err != nil {
			return nil, nil, err
		}
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  cfg.Organization,
			CommonName:    cfg.CommonName,
			Country:       cfg.Country,
			Locality:      cfg.Locality,
			Province:      cfg.Province,
			StreetAddress: cfg.StreetAddress,
			PostalCode:    cfg.PostalCode,
		},
		NotBefore: validFrom,
		NotAfter:  validFrom.Add(maxAge),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IPAddresses = append(template.IPAddresses, cfg.AltNames.IPs...)
	template.DNSNames = append(template.DNSNames, cfg.AltNames.DNSNames...)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCertificate, publicKey(certKey), caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)

	return cert, certKey, nil
}

// EncodeCertPEM returns PEM-endcoded certificate data
func EncodeCertPEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  CertificateBlockType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

// EncodePrivateKeyPEM returns PEM-encoded public data
func EncodePrivateKeyPEM(key rsa.PrivateKey) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(&key)

	block := pem.Block{
		Type:  PrivateKeyBlockType,
		Bytes: der,
	}
	return pem.EncodeToMemory(&block), nil
}

// EncodePrivateKeyPEM returns PEM-encoded private data
func EncodePublicKeyPEM(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return []byte{}, err
	}
	block := pem.Block{
		Type:  PublicKeyBlockType,
		Bytes: der,
	}
	return pem.EncodeToMemory(&block), nil
}

// MarshalPrivateKeyToPEM converts a known private key type of RSA or ECDSA to
// a PEM encoded block or returns an error.
func MarshalPrivateKeyToPEM(privateKey crypto.PrivateKey) ([]byte, error) {
	switch t := privateKey.(type) {
	case *ecdsa.PrivateKey:
		derBytes, err := x509.MarshalECPrivateKey(t)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  ECPrivateKeyBlockType,
			Bytes: derBytes,
		}
		return pem.EncodeToMemory(block), nil
	case *rsa.PrivateKey:
		block := &pem.Block{
			Type:  RSAPrivateKeyBlockType,
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		}
		return pem.EncodeToMemory(block), nil
	default:
		return nil, fmt.Errorf("private key is not a recognized type: %T", privateKey)
	}
}
