// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
)

// CertificateType is a value from the IANA TLS Certificate Types registry.
//
// https://www.rfc-editor.org/rfc/rfc7250#section-3
type CertificateType uint8

// Certificate types defined by RFC 7250.
const (
	CertificateTypeX509         CertificateType = 0
	CertificateTypeRawPublicKey CertificateType = 2
)

// ClientCertificateTypeOffer is the ClientHello client_certificate_type
// payload: the types the client can present, in preference order.
type ClientCertificateTypeOffer struct {
	Types []CertificateType
}

func (ClientCertificateTypeOffer) ExtensionType() Type { return TypeClientCertificateType }
func (c ClientCertificateTypeOffer) MarshalSize() int  { return 1 + len(c.Types) }

func (c ClientCertificateTypeOffer) MarshalData() ([]byte, error) {
	return marshalCertificateTypes(c.Types)
}

func (c *ClientCertificateTypeOffer) UnmarshalData(data []byte) error {
	types, err := unmarshalCertificateTypes(data)
	if err == nil {
		c.Types = types
	}

	return err
}

// ClientCertificateTypeSelection is the ServerHello client_certificate_type
// payload: the single type the client must present.
type ClientCertificateTypeSelection struct {
	Type CertificateType
}

func (ClientCertificateTypeSelection) ExtensionType() Type { return TypeClientCertificateType }
func (ClientCertificateTypeSelection) MarshalSize() int    { return 1 }

func (c ClientCertificateTypeSelection) MarshalData() ([]byte, error) {
	return []byte{byte(c.Type)}, nil
}

func (c *ClientCertificateTypeSelection) UnmarshalData(data []byte) error {
	if len(data) != 1 {
		return dtlserrors.ErrLengthMismatch
	}
	c.Type = CertificateType(data[0])

	return nil
}

// ServerCertificateTypeOffer is the ClientHello server_certificate_type
// payload: the types the client accepts from the server, in preference order.
type ServerCertificateTypeOffer struct {
	Types []CertificateType
}

func (ServerCertificateTypeOffer) ExtensionType() Type { return TypeServerCertificateType }
func (s ServerCertificateTypeOffer) MarshalSize() int  { return 1 + len(s.Types) }

func (s ServerCertificateTypeOffer) MarshalData() ([]byte, error) {
	return marshalCertificateTypes(s.Types)
}

func (s *ServerCertificateTypeOffer) UnmarshalData(data []byte) error {
	types, err := unmarshalCertificateTypes(data)
	if err == nil {
		s.Types = types
	}

	return err
}

// ServerCertificateTypeSelection is the ServerHello server_certificate_type
// payload: the single type of the server's Certificate.
type ServerCertificateTypeSelection struct {
	Type CertificateType
}

func (ServerCertificateTypeSelection) ExtensionType() Type { return TypeServerCertificateType }
func (ServerCertificateTypeSelection) MarshalSize() int    { return 1 }

func (s ServerCertificateTypeSelection) MarshalData() ([]byte, error) {
	return []byte{byte(s.Type)}, nil
}

func (s *ServerCertificateTypeSelection) UnmarshalData(data []byte) error {
	if len(data) != 1 {
		return dtlserrors.ErrLengthMismatch
	}
	s.Type = CertificateType(data[0])

	return nil
}

// CertificateType client_certificate_types<1..2^8-1>.
func marshalCertificateTypes(types []CertificateType) ([]byte, error) {
	if len(types) == 0 || len(types) > 0xff {
		return nil, dtlserrors.ErrLengthMismatch
	}
	out := make([]byte, 1, 1+len(types))
	out[0] = byte(len(types)) //nolint:gosec // length is bounded above.
	for _, t := range types {
		out = append(out, byte(t))
	}

	return out, nil
}

func unmarshalCertificateTypes(data []byte) ([]CertificateType, error) {
	if len(data) < 2 || int(data[0]) != len(data)-1 {
		return nil, dtlserrors.ErrLengthMismatch
	}
	types := make([]CertificateType, 0, len(data)-1)
	for _, b := range data[1:] {
		types = append(types, CertificateType(b))
	}

	return types, nil
}
