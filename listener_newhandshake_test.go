// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fiumaralabs/dtls/v3/pkg/crypto/selfsign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lwm2m patch: a client that reconnects from the address of an established
// association gets a new handshake (RFC 6347 §4.2.8). A spoofed ClientHello
// must not disturb the association, and a half-open handshake (its later
// flights lost) must not block the client's next attempt from that address.
func TestNewHandshakeFromSameAddress(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	ln, err := Listen("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	var served sync.WaitGroup
	conns := make(chan net.Conn, 8)
	served.Add(1)
	go func() { defer served.Done(); serveEcho(ln, conns) }()
	defer func() {
		// Close the server's conns, the superseded one included, so no
		// goroutine outlives the test.
		assert.NoError(t, ln.Close())
		served.Wait()
		close(conns)
		for c := range conns {
			_ = c.Close()
		}
	}()
	raddr := ln.Addr()
	clientConfig := &Config{InsecureSkipVerify: true}

	udp1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	laddr := udp1.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
	client1 := dialHandshake(t, udp1, raddr, clientConfig, 5*time.Second)
	defer func() { _ = client1.Close() }()
	echo(t, client1, "first")

	// A spoofed ClientHello from the client's address starts a pending
	// handshake but leaves the association alone.
	_, err = udp1.WriteTo(captureClientHello(t), raddr)
	require.NoError(t, err)
	echo(t, client1, "not hijacked")

	// The client loses its state, reconnects from the same port, and its
	// handshake stalls after the ClientHellos (flight 5 is lost).
	require.NoError(t, udp1.Close())
	udp2, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)
	stuck, err := Client(&clientHelloOnly{udp2}, raddr, clientConfig)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	assert.Error(t, stuck.HandshakeContext(ctx))
	cancel()
	_ = udp2.Close() // the failed handshake may have closed it

	// The next attempt from that port succeeds without waiting for the
	// stalled handshake (30 s on the server) to time out.
	udp3, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)
	defer func() { _ = udp3.Close() }()
	client3 := dialHandshake(t, &afterHelloVerify{PacketConn: udp3}, raddr, clientConfig, 5*time.Second)
	defer func() { _ = client3.Close() }()
	echo(t, client3, "reconnected")
}

// serveEcho accepts connections, sends them to conns and echoes what they
// read.
func serveEcho(ln net.Listener, conns chan<- net.Conn) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conns <- conn
		go func() {
			defer func() { _ = conn.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if conn.(*Conn).HandshakeContext(ctx) != nil { //nolint:forcetypeassert
				return
			}
			buf := make([]byte, 64)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				_, _ = conn.Write(buf[:n])
			}
		}()
	}
}

func dialHandshake(t *testing.T, pc net.PacketConn, raddr net.Addr, config *Config, timeout time.Duration) *Conn {
	t.Helper()
	client, err := Client(pc, raddr, config)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	require.NoError(t, client.HandshakeContext(ctx))

	return client
}

func echo(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	_, err := conn.Write([]byte(msg))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, string(buf[:n]))
}

// clientHelloOnly drops every datagram but ClientHellos.
type clientHelloOnly struct{ net.PacketConn }

func (c *clientHelloOnly) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > 13 && b[0] == 22 && b[13] == 1 {
		return c.PacketConn.WriteTo(b, addr)
	}

	return len(b), nil
}

// captureClientHello returns a client's first ClientHello.
func captureClientHello(t *testing.T) []byte {
	t.Helper()
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	client, err := Client(pc, sink.LocalAddr(), &Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.HandshakeContext(ctx) }()

	require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2048)
	n, _, err := sink.ReadFrom(buf)
	require.NoError(t, err)

	return buf[:n]
}

// afterHelloVerify drops handshake datagrams received before a
// HelloVerifyRequest. Retransmissions of the stalled handshake's flight 4 can
// reach the new socket before the server sees the new ClientHello; a real
// client would fail that attempt and retry.
type afterHelloVerify struct {
	net.PacketConn
	verified bool
}

func (c *afterHelloVerify) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || c.verified || n <= 13 || b[0] != 22 {
			return n, addr, err
		}
		if b[13] == 3 { // HelloVerifyRequest
			c.verified = true

			return n, addr, err
		}
	}
}
