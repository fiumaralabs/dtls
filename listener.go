// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"net"

	"github.com/pion/dtls/v4/internal/net/udp"
	dtlsnet "github.com/pion/dtls/v4/pkg/net"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
)

func packetListenerOptions(config *dtlsConfig) []udp.ListenerOption {
	opts := []udp.ListenerOption{
		udp.WithAcceptFilter(func(packet []byte) bool {
			pkts, _ := recordlayer.UnpackDatagram(packet, recordlayer.UnpackDatagramConfig{})
			if len(pkts) == 0 {
				return false
			}
			h, err := recordlayer.ParseRecord(pkts[0], 0)
			if err != nil {
				return false
			}

			return h.ContentType() == protocol.ContentTypeHandshake
		}),
		udp.WithNewHandshakeOnAddress(classifyFirstRecord),
		udp.WithReceiveBufferSize(config.ReceiveBufferSize),
	}
	// A non-empty local receive CID must also be supported by listener routing.
	if config.ReceiveCIDLength > 0 {
		opts = append(opts, udp.WithDatagramRouter(cidDatagramRouter(config.ReceiveCIDLength)))
	}

	return opts
}

// classifyFirstRecord reports whether the first record of a datagram has
// epoch 0 and, if it starts a ClientHello, returns the client random.
func classifyFirstRecord(packet []byte) (epochZero bool, clientRandom []byte) {
	pkts, _ := recordlayer.UnpackDatagram(packet, recordlayer.UnpackDatagramConfig{})
	if len(pkts) == 0 {
		return false, nil
	}
	record, err := recordlayer.ParseRecord(pkts[0], 0)
	if err != nil || record.IsUnified() || record.Epoch() != 0 {
		return false, nil
	}
	if record.ContentType() != protocol.ContentTypeHandshake {
		return true, nil
	}
	payload := record.Payload()
	var header handshake.Header
	// The random follows the header and the two-byte client_version.
	randomStart := handshake.HeaderLength + 2
	if header.Unmarshal(payload) != nil || header.Type != handshake.TypeClientHello ||
		header.FragmentOffset != 0 || len(payload) < randomStart+handshake.RandomLength {
		return true, nil
	}

	return true, payload[randomStart : randomStart+handshake.RandomLength]
}

func newListenerWithConfig(parent dtlsnet.PacketListener, config *dtlsConfig) net.Listener {
	return &listener{
		config: config,
		parent: parent,
	}
}

func buildListenerConfig(opts ...ServerOption) (*dtlsConfig, error) {
	config, err := buildServerConfig(opts...)
	if err != nil {
		return nil, err
	}
	if err = validateConfig(config); err != nil {
		return nil, err
	}

	return config, nil
}

func listenWithConfig(conn net.PacketConn, config *dtlsConfig) net.Listener {
	return newListenerWithConfig(udp.Listen(conn, packetListenerOptions(config)...), config)
}

// Listen creates a DTLS listener over an existing packet connection.
func Listen(conn net.PacketConn, opts ...ServerOption) (net.Listener, error) {
	config, err := buildListenerConfig(opts...)
	if err != nil {
		return nil, err
	}

	return listenWithConfig(conn, config), nil
}

// ListenAddr creates a DTLS listener bound to laddr.
func ListenAddr(network string, laddr *net.UDPAddr, opts ...ServerOption) (net.Listener, error) {
	config, err := buildListenerConfig(opts...)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}

	return listenWithConfig(conn, config), nil
}

// NewListener creates a DTLS listener which accepts connections from an inner packet listener.
func NewListener(inner dtlsnet.PacketListener, opts ...ServerOption) (net.Listener, error) {
	config, err := buildListenerConfig(opts...)
	if err != nil {
		return nil, err
	}

	return newListenerWithConfig(inner, config), nil
}

// listener represents a DTLS listener.
type listener struct {
	config *dtlsConfig
	parent dtlsnet.PacketListener
}

// Accept waits for and returns the next connection to the listener.
// You have to either close or read on all connection that are created.
func (l *listener) Accept() (net.Conn, error) {
	c, raddr, err := l.parent.Accept()
	if err != nil {
		return nil, err
	}

	conn, err := serverWithConfig(c, raddr, l.config)
	if err != nil {
		_ = c.Close()

		return nil, err
	}

	return conn, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
// Already Accepted connections are not closed.
func (l *listener) Close() error {
	return l.parent.Close()
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.parent.Addr()
}
