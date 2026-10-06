// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"github.com/fiumaralabs/dtls/v3/internal/util"
)

// MessageCertificate is a DTLS Handshake Message
// it can contain either a Client or Server Certificate
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
type MessageCertificate struct {
	Certificate [][]byte

	// RawPublicKey selects the RFC 7250 §3 form (lwm2m patch): the body is
	// a single ASN.1_subjectPublicKeyInfo<1..2^24-1>, Certificate[0],
	// instead of a certificate_list.
	RawPublicKey bool
}

// Type returns the Handshake Type.
func (m MessageCertificate) Type() Type {
	return TypeCertificate
}

const (
	handshakeMessageCertificateLengthFieldSize = 3
)

// Marshal encodes the Handshake.
func (m *MessageCertificate) Marshal() ([]byte, error) {
	if m.RawPublicKey {
		if len(m.Certificate) != 1 || len(m.Certificate[0]) == 0 {
			return nil, errLengthMismatch
		}
		out := make([]byte, handshakeMessageCertificateLengthFieldSize,
			handshakeMessageCertificateLengthFieldSize+len(m.Certificate[0]))
		util.PutBigEndianUint24(out, uint32(len(m.Certificate[0]))) //nolint:gosec // G115

		return append(out, m.Certificate[0]...), nil
	}
	total := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		total += handshakeMessageCertificateLengthFieldSize + len(cert)
	}

	out := make([]byte, total)

	// Total Payload Size
	//nolint:gosec // G115
	util.PutBigEndianUint24(out, uint32(total-handshakeMessageCertificateLengthFieldSize))
	offset := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		// Certificate Length
		//nolint:gosec // G115
		util.PutBigEndianUint24(out[offset:], uint32(len(cert)))
		offset += handshakeMessageCertificateLengthFieldSize

		// Certificate body
		copy(out[offset:], cert)
		offset += len(cert)
	}

	return out, nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageCertificate) Unmarshal(data []byte) error {
	if len(data) < handshakeMessageCertificateLengthFieldSize {
		return errBufferTooSmall
	}

	if certificateBodyLen := int(util.BigEndianUint24(
		data,
	)); certificateBodyLen+handshakeMessageCertificateLengthFieldSize != len(data) {
		return errLengthMismatch
	}

	// lwm2m patch: a raw public key body (RFC 7250) is one DER
	// SubjectPublicKeyInfo, so it starts with a SEQUENCE tag (0x30) where a
	// certificate_list has the high byte of a 24-bit length. A list entry
	// that large (>= 3 MiB) cannot occur in DTLS, so the forms are disjoint.
	// The handshake checks the form against the negotiated certificate type.
	if len(data) > handshakeMessageCertificateLengthFieldSize && data[handshakeMessageCertificateLengthFieldSize] == 0x30 {
		m.Certificate = [][]byte{append([]byte{}, data[handshakeMessageCertificateLengthFieldSize:]...)}
		m.RawPublicKey = true

		return nil
	}

	offset := handshakeMessageCertificateLengthFieldSize
	for offset < len(data) {
		certificateLen := int(util.BigEndianUint24(data[offset:]))
		offset += handshakeMessageCertificateLengthFieldSize

		if offset+certificateLen > len(data) {
			return errLengthMismatch
		}

		m.Certificate = append(m.Certificate, append([]byte{}, data[offset:offset+certificateLen]...))
		offset += certificateLen
	}

	return nil
}
