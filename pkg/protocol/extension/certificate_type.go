// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// lwm2m patch: RFC 7250 client_certificate_type / server_certificate_type.

package extension

import "encoding/binary"

// CertificateType is a TLS Certificate Type (IANA "TLS Certificate Types").
type CertificateType uint8

// Certificate types from RFC 7250 §3.
const (
	CertificateTypeX509         CertificateType = 0
	CertificateTypeRawPublicKey CertificateType = 2
)

// Extension type values from RFC 7250 §3.
const (
	ClientCertificateTypeTypeValue TypeValue = 19
	ServerCertificateTypeTypeValue TypeValue = 20
)

// certificateTypes is the common body of both RFC 7250 extensions. In a
// ClientHello it is a list (1-byte length + types), in a ServerHello a
// single type. The extension data length tells them apart: a list is at
// least two bytes long.
type certificateTypes struct {
	Types    []CertificateType
	Selected bool // ServerHello form: exactly one type, no list length
}

func (c *certificateTypes) marshal(typ TypeValue) ([]byte, error) {
	var body []byte
	if c.Selected {
		if len(c.Types) != 1 {
			return nil, errInvalidCertificateTypes
		}
		body = []byte{byte(c.Types[0])}
	} else {
		if len(c.Types) == 0 || len(c.Types) > 255 {
			return nil, errInvalidCertificateTypes
		}
		body = append(body, byte(len(c.Types))) //nolint:gosec // G115, checked above
		for _, ct := range c.Types {
			body = append(body, byte(ct))
		}
	}
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint16(out, uint16(typ))
	binary.BigEndian.PutUint16(out[2:], uint16(len(body))) //nolint:gosec // G115, bounded above

	return append(out, body...), nil
}

func (c *certificateTypes) unmarshal(t TypeValue, data []byte) error {
	if len(data) < 4 {
		return errBufferTooSmall
	}
	if TypeValue(binary.BigEndian.Uint16(data)) != t {
		return errInvalidExtensionType
	}
	n := int(binary.BigEndian.Uint16(data[2:]))
	if len(data) < 4+n || n == 0 {
		return errLengthMismatch
	}
	body := data[4 : 4+n]
	if n == 1 {
		c.Selected = true
		c.Types = []CertificateType{CertificateType(body[0])}

		return nil
	}
	if int(body[0]) != n-1 {
		return errLengthMismatch
	}
	c.Types = nil
	for _, b := range body[1:] {
		c.Types = append(c.Types, CertificateType(b))
	}

	return nil
}

// ClientCertificateType is the client_certificate_type extension (RFC 7250 §3).
type ClientCertificateType struct{ certificateTypes }

// TypeValue returns the extension TypeValue.
func (ClientCertificateType) TypeValue() TypeValue { return ClientCertificateTypeTypeValue }

// Marshal encodes the extension.
func (c *ClientCertificateType) Marshal() ([]byte, error) { return c.marshal(c.TypeValue()) }

// Unmarshal populates the extension from encoded data.
func (c *ClientCertificateType) Unmarshal(data []byte) error { return c.unmarshal(c.TypeValue(), data) }

// ServerCertificateType is the server_certificate_type extension (RFC 7250 §3).
type ServerCertificateType struct{ certificateTypes }

// TypeValue returns the extension TypeValue.
func (ServerCertificateType) TypeValue() TypeValue { return ServerCertificateTypeTypeValue }

// Marshal encodes the extension.
func (c *ServerCertificateType) Marshal() ([]byte, error) { return c.marshal(c.TypeValue()) }

// Unmarshal populates the extension from encoded data.
func (c *ServerCertificateType) Unmarshal(data []byte) error { return c.unmarshal(c.TypeValue(), data) }

// NewClientCertificateType returns the ClientHello (list) or, with
// selected, the ServerHello (single type) form.
func NewClientCertificateType(selected bool, types ...CertificateType) *ClientCertificateType {
	return &ClientCertificateType{certificateTypes{Types: types, Selected: selected}}
}

// NewServerCertificateType returns the ClientHello (list) or, with
// selected, the ServerHello (single type) form.
func NewServerCertificateType(selected bool, types ...CertificateType) *ServerCertificateType {
	return &ServerCertificateType{certificateTypes{Types: types, Selected: selected}}
}
