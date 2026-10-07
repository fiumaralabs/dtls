// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

func unsupportedCertificate() *alert.Alert {
	return &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedCertificate}
}

// certificateTypeOffers returns the client's RFC 7250 ClientHello extensions.
func certificateTypeOffers(cfg *dtlsconfig.HandshakeConfig) []extension.Value {
	var extensions []extension.Value
	if cfg.ClientCertificateTypes != nil {
		extensions = append(extensions, &extension.ClientCertificateTypeOffer{Types: cfg.ClientCertificateTypes})
	}
	if cfg.ServerCertificateTypes != nil {
		extensions = append(extensions, &extension.ServerCertificateTypeOffer{Types: cfg.ServerCertificateTypes})
	}

	return extensions
}

// acceptsX509 reports whether a configured type list allows X.509, which an
// absent extension implies. No list means X.509 only.
func acceptsX509(types []extension.CertificateType) bool {
	return types == nil || slices.Contains(types, extension.CertificateTypeX509)
}

// selectCertificateType picks the first local type that the peer offered.
// No local preference means X.509 only.
func selectCertificateType(local, offered []extension.CertificateType) (extension.CertificateType, bool) {
	if len(local) == 0 {
		local = []extension.CertificateType{extension.CertificateTypeX509}
	}
	for _, t := range local {
		if slices.Contains(offered, t) {
			return t, true
		}
	}

	return 0, false
}

// negotiateCertificateType selects the type for one side's credential from
// the client's offer of typ. Without an offer only X.509 is possible.
func negotiateCertificateType(
	offer negotiation.ClientHelloSnapshot, typ extension.Type, local []extension.CertificateType,
) (selected extension.CertificateType, offered bool, dtlsAlert *alert.Alert, err error) {
	raw, offered := offer.Extension(typ)
	if !offered {
		if !acceptsX509(local) {
			return 0, false, unsupportedCertificate(), dtlserrors.ErrUnsupportedCertificateType
		}

		return extension.CertificateTypeX509, false, nil, nil
	}
	// Both offers share one payload format.
	var parsed extension.ClientCertificateTypeOffer
	if err = parsed.UnmarshalData(raw.Data); err != nil {
		return 0, true, &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError}, err
	}
	selected, found := selectCertificateType(local, parsed.Types)
	if !found {
		return 0, true, unsupportedCertificate(), dtlserrors.ErrUnsupportedCertificateType
	}

	return selected, true, nil, nil
}

// negotiateCertificateTypes selects the server's and the client's certificate
// types and returns the ServerHello extensions announcing them. A server
// without configured types ignores the extensions, as one that does not
// implement RFC 7250 would.
//
// https://www.rfc-editor.org/rfc/rfc7250#section-4.2
func negotiateCertificateTypes(
	state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, offer negotiation.ClientHelloSnapshot,
) ([]extension.Value, *alert.Alert, error) {
	state.LocalCertificateType = extension.CertificateTypeX509
	state.RemoteCertificateType = extension.CertificateTypeX509
	if state.CipherSuite.AuthenticationType() != cryptosuite.AuthenticationTypeCertificate ||
		(cfg.ServerCertificateTypes == nil && cfg.ClientCertificateTypes == nil) {
		return nil, nil, nil
	}

	var extensions []extension.Value
	selected, offered, alertPtr, err := negotiateCertificateType(offer, extension.TypeServerCertificateType, cfg.ServerCertificateTypes)
	if err != nil {
		return nil, alertPtr, err
	}
	state.LocalCertificateType = selected
	if offered {
		extensions = append(extensions, &extension.ServerCertificateTypeSelection{Type: selected})
	}

	// The client's type is only announced with a CertificateRequest.
	if cfg.ClientAuth == dtlsconfig.NoClientCert {
		return extensions, nil, nil
	}
	selected, offered, alertPtr, err = negotiateCertificateType(offer, extension.TypeClientCertificateType, cfg.ClientCertificateTypes)
	if err != nil {
		return nil, alertPtr, err
	}
	state.RemoteCertificateType = selected
	if offered {
		extensions = append(extensions, &extension.ClientCertificateTypeSelection{Type: selected})
	}

	return extensions, nil, nil
}

// parseCertificateTypeSelections applies the server's selections from its
// ServerHello on the client.
func parseCertificateTypeSelections(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, extensions []extension.Value) (*alert.Alert, error) {
	state.LocalCertificateType = extension.CertificateTypeX509
	state.RemoteCertificateType = extension.CertificateTypeX509
	serverTypeSelected := false
	for _, v := range extensions {
		switch ext := v.(type) {
		case *extension.ClientCertificateTypeSelection:
			if !slices.Contains(cfg.ClientCertificateTypes, ext.Type) {
				return unsupportedCertificate(), dtlserrors.ErrUnsupportedCertificateType
			}
			state.LocalCertificateType = ext.Type
		case *extension.ServerCertificateTypeSelection:
			if !slices.Contains(cfg.ServerCertificateTypes, ext.Type) {
				return unsupportedCertificate(), dtlserrors.ErrUnsupportedCertificateType
			}
			state.RemoteCertificateType = ext.Type
			serverTypeSelected = true
		}
	}
	// Without the extension the server's certificate is X.509.
	if !serverTypeSelected && !acceptsX509(cfg.ServerCertificateTypes) {
		return unsupportedCertificate(), dtlserrors.ErrUnsupportedCertificateType
	}

	return nil, nil //nolint:nilnil
}

// certificateMessage builds the Certificate message for a local credential.
// A raw public key is the SubjectPublicKeyInfo of the credential's private
// key.
func certificateMessage(certificate *tls.Certificate, typ extension.CertificateType) (*handshake.MessageCertificate, error) {
	if typ != extension.CertificateTypeRawPublicKey {
		return &handshake.MessageCertificate{Certificate: certificate.Certificate}, nil
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, dtlserrors.ErrInvalidPrivateKey
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	return &handshake.MessageCertificate{Certificate: [][]byte{spki}, RawPublicKey: true}, nil
}

// checkCertificateForm rejects a Certificate message whose form does not
// match the negotiated certificate type.
func checkCertificateForm(message *handshake.MessageCertificate, typ extension.CertificateType) (*alert.Alert, error) {
	if len(message.Certificate) == 0 {
		return nil, nil //nolint:nilnil
	}
	if message.RawPublicKey != (typ == extension.CertificateTypeRawPublicKey) {
		return unsupportedCertificate(), dtlserrors.ErrUnsupportedCertificateType
	}
	if message.RawPublicKey {
		if _, err := x509.ParsePKIXPublicKey(message.Certificate[0]); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
	}

	return nil, nil //nolint:nilnil
}
