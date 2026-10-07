// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateTypeOffer(t *testing.T) {
	for _, value := range []interface {
		Value
		PayloadUnmarshaller
	}{
		&ClientCertificateTypeOffer{Types: []CertificateType{CertificateTypeRawPublicKey, CertificateTypeX509}},
		&ServerCertificateTypeOffer{Types: []CertificateType{CertificateTypeRawPublicKey, CertificateTypeX509}},
	} {
		raw, err := value.MarshalData()
		require.NoError(t, err)
		assert.Equal(t, []byte{0x02, 0x02, 0x00}, raw)
		assert.Equal(t, len(raw), value.MarshalSize())
		require.NoError(t, value.UnmarshalData(raw))
	}

	parsed := &ClientCertificateTypeOffer{}
	require.NoError(t, parsed.UnmarshalData([]byte{0x01, 0x02}))
	assert.Equal(t, []CertificateType{CertificateTypeRawPublicKey}, parsed.Types)

	for _, data := range [][]byte{{}, {0x00}, {0x01}, {0x02, 0x02}, {0x01, 0x02, 0x00}} {
		assert.ErrorIs(t, parsed.UnmarshalData(data), dtlserrors.ErrLengthMismatch, "%x", data)
	}

	_, err := ClientCertificateTypeOffer{}.MarshalData()
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
}

func TestCertificateTypeSelection(t *testing.T) {
	client := &ClientCertificateTypeSelection{}
	require.NoError(t, client.UnmarshalData([]byte{0x02}))
	assert.Equal(t, CertificateTypeRawPublicKey, client.Type)
	raw, err := client.MarshalData()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x02}, raw)

	server := &ServerCertificateTypeSelection{}
	require.NoError(t, server.UnmarshalData([]byte{0x00}))
	assert.Equal(t, CertificateTypeX509, server.Type)

	// A ServerHello carries one type, not a list.
	assert.ErrorIs(t, client.UnmarshalData([]byte{0x01, 0x02}), dtlserrors.ErrLengthMismatch)
	assert.ErrorIs(t, server.UnmarshalData(nil), dtlserrors.ErrLengthMismatch)
}
