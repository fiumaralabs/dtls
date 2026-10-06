// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// lwm2m patch: RFC 7250 raw public keys.

package dtls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"slices"

	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// CertificateType is a TLS certificate type (RFC 7250).
type CertificateType = extension.CertificateType

// Certificate types.
const (
	CertificateTypeX509         = extension.CertificateTypeX509
	CertificateTypeRawPublicKey = extension.CertificateTypeRawPublicKey
)

// selectCertificateType picks the first local type the peer offered. An
// absent extension (offered == nil) means X.509 only (RFC 7250 §4.1).
func selectCertificateType(local, offered []CertificateType) (CertificateType, bool) {
	if offered == nil {
		return CertificateTypeX509, len(local) == 0 || slices.Contains(local, CertificateTypeX509)
	}
	if len(local) == 0 {
		local = []CertificateType{CertificateTypeX509}
	}
	for _, t := range local {
		if slices.Contains(offered, t) {
			return t, true
		}
	}

	return 0, false
}

// certificateMessage builds the Certificate message for our credential.
func certificateMessage(cert *tls.Certificate, t CertificateType) (*handshake.MessageCertificate, error) {
	if t != CertificateTypeRawPublicKey {
		return &handshake.MessageCertificate{Certificate: cert.Certificate}, nil
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errInvalidPrivateKey
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	return &handshake.MessageCertificate{Certificate: [][]byte{spki}, RawPublicKey: true}, nil
}

// checkCertificateForm rejects a Certificate message whose form does not
// match the negotiated type.
func checkCertificateForm(m *handshake.MessageCertificate, t CertificateType) error {
	if len(m.Certificate) == 0 {
		return nil
	}
	if m.RawPublicKey != (t == CertificateTypeRawPublicKey) {
		return errInvalidCertificate
	}
	if m.RawPublicKey {
		if _, err := x509.ParsePKIXPublicKey(m.Certificate[0]); err != nil {
			return errInvalidCertificate
		}
	}

	return nil
}

// parsePeerCredential returns the peer's end-entity certificate, or for a
// raw public key a Certificate carrying only the key.
func parsePeerCredential(raw []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(raw)
	if err == nil {
		return c, nil
	}
	pub, perr := x509.ParsePKIXPublicKey(raw)
	if perr != nil {
		return nil, err
	}

	return &x509.Certificate{PublicKey: pub, RawSubjectPublicKeyInfo: raw}, nil
}

// appendCertificateTypeOffers adds the client's RFC 7250 offers.
func appendCertificateTypeOffers(exts []extension.Extension, cfg *handshakeConfig) []extension.Extension {
	if cfg.clientCertificateTypes != nil {
		exts = append(exts, extension.NewClientCertificateType(false, cfg.clientCertificateTypes...))
	}
	if cfg.serverCertificateTypes != nil {
		exts = append(exts, extension.NewServerCertificateType(false, cfg.serverCertificateTypes...))
	}

	return exts
}

// negotiateCertificateTypes selects the server's and the client's
// certificate types for a certificate suite and returns the ServerHello
// extensions announcing them (RFC 7250 §4.2).
func negotiateCertificateTypes(state *State, cfg *handshakeConfig) ([]extension.Extension, *alert.Alert, error) {
	state.localCertificateType, state.remoteCertificateType = CertificateTypeX509, CertificateTypeX509
	if state.cipherSuite.AuthenticationType() != CipherSuiteAuthenticationTypeCertificate {
		return nil, nil, nil
	}
	unsupported := &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedCertificate}
	var exts []extension.Extension
	t, ok := selectCertificateType(cfg.serverCertificateTypes, state.remoteOfferedServerCertType)
	if !ok {
		return nil, unsupported, errInvalidCertificate
	}
	state.localCertificateType = t
	if state.remoteOfferedServerCertType != nil {
		exts = append(exts, extension.NewServerCertificateType(true, t))
	}
	if cfg.clientAuth > NoClientCert {
		t, ok = selectCertificateType(cfg.clientCertificateTypes, state.remoteOfferedClientCertType)
		if !ok {
			return nil, unsupported, errInvalidCertificate
		}
		state.remoteCertificateType = t
		if state.remoteOfferedClientCertType != nil {
			exts = append(exts, extension.NewClientCertificateType(true, t))
		}
	}

	return exts, nil, nil
}
