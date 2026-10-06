// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawKeyCredential returns a credential for a raw public key and its
// SubjectPublicKeyInfo. The certificate bytes are never sent.
func rawKeyCredential(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{[]byte("unused")}, PrivateKey: key}, spki
}

func expectRawKey(t *testing.T, spki []byte) func([][]byte, [][]*x509.Certificate) error {
	t.Helper()

	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		assert.Empty(t, chains)
		if len(rawCerts) != 1 || !bytes.Equal(rawCerts[0], spki) {
			return errors.New("unexpected raw public key") //nolint:err113
		}

		return nil
	}
}

func assertAlert(t *testing.T, err error, description alert.Description) {
	t.Helper()
	var alertErr *alertError
	require.ErrorAs(t, err, &alertErr)
	assert.Equal(t, description, alertErr.Description)
}

func TestRawPublicKeyHandshake(t *testing.T) {
	rpk := []CertificateType{CertificateTypeRawPublicKey}
	suite := WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

	t.Run("ServerRawKey", func(t *testing.T) {
		serverCred, serverKey := rawKeyCredential(t)
		client, server := handshakePair(t,
			[]ClientOption{suite, WithServerCertificateTypes(rpk...), WithVerifyPeerCertificate(expectRawKey(t, serverKey))},
			[]ServerOption{suite, WithServerCertificateTypes(rpk...), WithCertificates(serverCred)},
		)
		require.NoError(t, client.handshakeError)
		require.NoError(t, server.handshakeError)
		state, ok := client.conn.ConnectionState()
		require.True(t, ok)
		assert.Equal(t, [][]byte{serverKey}, state.PeerCertificates)
	})

	t.Run("MutualRawKey", func(t *testing.T) {
		serverCred, serverKey := rawKeyCredential(t)
		clientCred, clientKey := rawKeyCredential(t)
		client, server := handshakePair(t,
			[]ClientOption{
				suite, WithServerCertificateTypes(rpk...), WithClientCertificateTypes(rpk...),
				WithCertificates(clientCred), WithVerifyPeerCertificate(expectRawKey(t, serverKey)),
			},
			[]ServerOption{
				suite, WithServerCertificateTypes(rpk...), WithClientCertificateTypes(rpk...),
				WithCertificates(serverCred), WithClientAuth(RequireAndVerifyClientCert),
				WithVerifyPeerCertificate(expectRawKey(t, clientKey)),
			},
		)
		require.NoError(t, client.handshakeError)
		require.NoError(t, server.handshakeError)
		state, ok := server.conn.ConnectionState()
		require.True(t, ok)
		assert.Equal(t, [][]byte{clientKey}, state.PeerCertificates)
	})

	t.Run("RawKeyClientX509Server", func(t *testing.T) {
		serverCert, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		clientCred, clientKey := rawKeyCredential(t)
		client, server := handshakePair(t,
			[]ClientOption{suite, WithClientCertificateTypes(rpk...), WithCertificates(clientCred), WithInsecureSkipVerify(true)},
			[]ServerOption{
				suite, WithClientCertificateTypes(CertificateTypeRawPublicKey, CertificateTypeX509),
				WithCertificates(serverCert), WithClientAuth(RequireAndVerifyClientCert),
				WithVerifyPeerCertificate(expectRawKey(t, clientKey)),
			},
		)
		require.NoError(t, client.handshakeError)
		require.NoError(t, server.handshakeError)
	})

	t.Run("NoCommonServerType", func(t *testing.T) {
		serverCert, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		client, server := handshakePair(t,
			[]ClientOption{suite, WithServerCertificateTypes(rpk...), WithInsecureSkipVerify(true)},
			[]ServerOption{suite, WithServerCertificateTypes(CertificateTypeX509), WithCertificates(serverCert)},
		)
		require.ErrorIs(t, server.handshakeError, dtlserrors.ErrUnsupportedCertificateType)
		assertAlert(t, client.handshakeError, alert.UnsupportedCertificate)
	})

	t.Run("ServerIgnoresOffersWithoutConfiguration", func(t *testing.T) {
		// A server that does not opt in behaves like one without RFC 7250.
		serverCert, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		client, server := handshakePair(t,
			[]ClientOption{suite, WithServerCertificateTypes(CertificateTypeRawPublicKey, CertificateTypeX509), WithInsecureSkipVerify(true)},
			[]ServerOption{suite, WithCertificates(serverCert)},
		)
		require.NoError(t, client.handshakeError)
		require.NoError(t, server.handshakeError)
	})

	t.Run("RawKeyOnlyClientRejectsX509Server", func(t *testing.T) {
		serverCert, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		client, _ := handshakePair(t,
			[]ClientOption{suite, WithServerCertificateTypes(rpk...), WithInsecureSkipVerify(true)},
			[]ServerOption{suite, WithCertificates(serverCert)},
		)
		require.ErrorIs(t, client.handshakeError, dtlserrors.ErrUnsupportedCertificateType)
	})

	t.Run("UnverifiedRawKey", func(t *testing.T) {
		serverCred, _ := rawKeyCredential(t)
		client, _ := handshakePair(t,
			[]ClientOption{suite, WithServerCertificateTypes(rpk...)},
			[]ServerOption{suite, WithServerCertificateTypes(rpk...), WithCertificates(serverCred)},
		)
		require.ErrorIs(t, client.handshakeError, dtlserrors.ErrUnverifiedRawPublicKey)
	})

	t.Run("RejectedRawKey", func(t *testing.T) {
		serverCred, _ := rawKeyCredential(t)
		_, otherKey := rawKeyCredential(t)
		client, server := handshakePair(t,
			[]ClientOption{suite, WithServerCertificateTypes(rpk...), WithVerifyPeerCertificate(expectRawKey(t, otherKey))},
			[]ServerOption{suite, WithServerCertificateTypes(rpk...), WithCertificates(serverCred)},
		)
		require.Error(t, client.handshakeError)
		assertAlert(t, server.handshakeError, alert.BadCertificate)
	})
}

func TestCertificateTypesOptions(t *testing.T) {
	cred, _ := rawKeyCredential(t)
	for name, test := range map[string]struct {
		opts []ClientOption
		err  error
	}{
		"Empty":       {[]ClientOption{WithServerCertificateTypes()}, dtlserrors.ErrEmptyCertificateTypes},
		"Unsupported": {[]ClientOption{WithClientCertificateTypes(1)}, dtlserrors.ErrUnsupportedCertificateType},
		"DTLS13": {
			[]ClientOption{WithServerCertificateTypes(CertificateTypeRawPublicKey), WithMaxVersion(protocol.Version1_3)},
			dtlserrors.ErrCertificateTypesRequireDTLS12,
		},
	} {
		t.Run(name, func(t *testing.T) {
			ca, cb := packetPipe()
			defer func() {
				_ = ca.Close()
				_ = cb.Close()
			}()
			_, err := Client(ca, ca.RemoteAddr(), append(test.opts, WithCertificates(cred))...)
			assert.ErrorIs(t, err, test.err)
		})
	}
}
