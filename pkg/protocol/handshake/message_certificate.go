// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/util"
)

// MessageCertificate is a DTLS Handshake Message
// it can contain either a Client or Server Certificate
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
type MessageCertificate struct {
	Certificate [][]byte

	// RawPublicKey selects the raw public key form negotiated with the
	// certificate type extensions: the body is a single DER
	// SubjectPublicKeyInfo, Certificate[0], instead of a certificate_list.
	//
	// https://www.rfc-editor.org/rfc/rfc7250#section-3
	RawPublicKey bool
}

// Type returns the Handshake Type.
func (m MessageCertificate) Type() Type {
	return TypeCertificate
}

const (
	handshakeMessageCertificateLengthFieldSize = 3
	asn1SequenceTag                            = 0x30
)

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageCertificate) MarshalSize() int {
	if m.RawPublicKey {
		size := handshakeMessageCertificateLengthFieldSize
		if len(m.Certificate) > 0 {
			size += len(m.Certificate[0])
		}

		return size
	}
	total := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		total += handshakeMessageCertificateLengthFieldSize + len(cert)
	}

	return total
}

// Marshal encodes the Handshake.
func (m *MessageCertificate) Marshal() ([]byte, error) {
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageCertificate) MarshalTo(out []byte) (int, error) {
	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}
	if m.RawPublicKey {
		if len(m.Certificate) != 1 || len(m.Certificate[0]) == 0 {
			return 0, dtlserrors.ErrLengthMismatch
		}
		//nolint:gosec // G115
		util.PutBigEndianUint24(out, uint32(len(m.Certificate[0])))

		return handshakeMessageCertificateLengthFieldSize + copy(out[handshakeMessageCertificateLengthFieldSize:], m.Certificate[0]), nil
	}
	// Total Payload MarshalSize
	//nolint:gosec // G115
	util.PutBigEndianUint24(out, uint32(m.MarshalSize()-handshakeMessageCertificateLengthFieldSize))
	offset := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		// Certificate Length
		//nolint:gosec // G115
		util.PutBigEndianUint24(out[offset:], uint32(len(cert)))
		offset += handshakeMessageCertificateLengthFieldSize

		// Certificate body
		offset += copy(out[offset:], cert)
	}

	return m.MarshalSize(), nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageCertificate) Unmarshal(data []byte) error {
	if len(data) < handshakeMessageCertificateLengthFieldSize {
		return dtlserrors.ErrBufferTooSmall
	}

	if certificateBodyLen := int(util.BigEndianUint24(data)); certificateBodyLen+handshakeMessageCertificateLengthFieldSize != len(data) {
		return dtlserrors.ErrLengthMismatch
	}

	// A raw public key body is one DER SubjectPublicKeyInfo, which starts
	// with a SEQUENCE tag (0x30). In a certificate_list that byte is the high
	// byte of the first entry's 24-bit length, which would mean an entry of
	// at least 3 MiB, larger than the fragment buffer accepts. The handshake
	// checks the form against the negotiated certificate type.
	if len(data) > handshakeMessageCertificateLengthFieldSize && data[handshakeMessageCertificateLengthFieldSize] == asn1SequenceTag {
		m.Certificate = [][]byte{bytes.Clone(data[handshakeMessageCertificateLengthFieldSize:])}
		m.RawPublicKey = true

		return nil
	}

	offset := handshakeMessageCertificateLengthFieldSize
	for offset < len(data) {
		certificateLen := int(util.BigEndianUint24(data[offset:]))
		offset += handshakeMessageCertificateLengthFieldSize

		if offset+certificateLen > len(data) {
			return dtlserrors.ErrLengthMismatch
		}

		m.Certificate = append(m.Certificate, bytes.Clone(data[offset:offset+certificateLen]))
		offset += certificateLen
	}

	return nil
}
