/*
Copyright 2022 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// CertPool is a set of certificates.
type CertPool struct {
	certificatesHashes map[[32]byte]struct{}
	certificates       []*x509.Certificate
	filterExpired      bool
	filterDuplicates   bool
}

// newCertPool returns a new, empty CertPool.
func NewCertPool(filterExpired bool, filterDuplicates bool) *CertPool {
	return &CertPool{
		certificates:       make([]*x509.Certificate, 0),
		filterExpired:      filterExpired,
		filterDuplicates:   filterDuplicates,
		certificatesHashes: make(map[[32]byte]struct{}),
	}
}

// Append certificate to a pool
func (cp *CertPool) appendCertFromPEM(pemData []byte) error {
	if pemData == nil {
		return fmt.Errorf("certificate data can't be nil")
	}

	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)

		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			// only certificates are allowed in a bundle
			return fmt.Errorf("invalid PEM block in bundle: only CERTIFICATE blocks are permitted but found '%s'", block.Type)
		}

		if len(block.Headers) != 0 {
			return fmt.Errorf("invalid PEM block in bundle; blocks are not permitted to have PEM headers")
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// the presence of an invalid cert (including things which aren't certs)
			// should cause the bundle to be rejected
			return fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
		}

		if certificate == nil {
			return fmt.Errorf("failed appending a certificate: certificate is nil")
		}

		if cp.filterExpired && time.Now().After(certificate.NotAfter) {
			continue
		}

		if cp.filterDuplicates {
			if cp.isDuplicate(certificate) {
				continue
			}
		}

		cp.certificates = append(cp.certificates, certificate)
	}

	return nil
}

// Get PEM certificates from pool
func (cp *CertPool) getCertsPEM() [][]byte {
	var certsData [][]byte = make([][]byte, len(cp.certificates))

	for i, cert := range cp.certificates {
		certsData[i] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}

	return certsData
}

// Get certificates quantity in the certificates pool
func (cp *CertPool) GetCertsQuantity() int {
	return len(cp.certificates)
}

// Check deplicates of certificate in the certificates pool
func (cp *CertPool) isDuplicate(cert *x509.Certificate) bool {
	hash := sha256.Sum256(cert.Raw)
	// check existence of the hash
	if _, ok := cp.certificatesHashes[hash]; !ok {
		cp.certificatesHashes[hash] = struct{}{}
		return false
	}

	return true
}

// Get the full list of x509 Certificates from the certificates pool
func (cp *CertPool) getCertsList() []*x509.Certificate {
	return cp.certificates
}
