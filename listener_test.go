// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client that loses its state and handshakes again from the same address
// must get a new connection (RFC 6347 Section 4.2.8), while the old one stays
// usable until the new handshake completes.
func TestListenerNewHandshakeFromSameAddress(t *testing.T) {
	for name, tc := range map[string]struct {
		version protocol.Version
		cid     bool
	}{
		"1.2":     {version: protocol.Version1_2},
		"1.2/CID": {version: protocol.Version1_2, cid: true},
		"1.3":     {version: protocol.Version1_3},
		"1.3/CID": {version: protocol.Version1_3, cid: true},
	} {
		t.Run(name, func(t *testing.T) {
			testListenerNewHandshakeFromSameAddress(t, tc.version, tc.cid)
		})
	}
}

func testListenerNewHandshakeFromSameAddress(t *testing.T, version protocol.Version, cid bool) {
	t.Helper()
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	opts := []ServerOption{WithCertificates(cert), WithMaxVersion(version)}
	clientOpts := []ClientOption{WithInsecureSkipVerify(true), WithMaxVersion(version)}
	if cid {
		opts = append(opts, WithConnectionID(RandomCIDGenerator(8), CIDPathMigrationReject))
		clientOpts = append(clientOpts, WithConnectionID(OnlySendCIDGenerator(), CIDPathMigrationReject))
	}
	ln, err := ListenAddr("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, opts...)
	require.NoError(t, err)
	defer func() { assert.NoError(t, ln.Close()) }()
	accepted := serveEcho(ln)
	raddr := ln.Addr()

	udp1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	laddr := udp1.LocalAddr()
	pc1 := &handshakeWatcher{PacketConn: udp1, seen: make(chan struct{})}
	client1 := dialHandshake(t, pc1, raddr, clientOpts)
	echo(t, client1, "first")
	first := <-accepted

	// A ClientHello that never completes, as from an off-path attacker
	// spoofing the client's address, must not take the address over.
	pc1.armed.Store(true)
	for _, datagram := range captureClientHello(t, version) {
		_, err = udp1.WriteTo(datagram, raddr)
		require.NoError(t, err)
	}
	select {
	case <-pc1.seen:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "no reply to the second ClientHello")
	}
	echo(t, client1, "not hijacked")

	// The client forgets the association without sending close_notify.
	require.NoError(t, udp1.Close())

	pc2, err := net.ListenUDP("udp", laddr.(*net.UDPAddr)) //nolint:forcetypeassert
	require.NoError(t, err)
	defer func() { _ = pc2.Close() }()
	second := dialHandshake(t, pc2, raddr, clientOpts)
	echo(t, second, "second")
	assert.NotSame(t, first, <-accepted)
	// The previous association is abandoned once the new one is verified.
	_, err = first.Write([]byte("stale"))
	assert.Error(t, err)
	echo(t, second, "still routed")
}

// serveEcho accepts connections and echoes what they read. It reports each
// connection whose handshake completed.
func serveEcho(ln net.Listener) <-chan net.Conn {
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if conn.(*Conn).HandshakeContext(ctx) != nil { //nolint:forcetypeassert
					_ = conn.Close()

					return
				}
				accepted <- conn
				buf := make([]byte, 64)
				for {
					n, readErr := conn.Read(buf)
					if readErr != nil {
						return
					}
					_, _ = conn.Write(buf[:n])
				}
			}()
		}
	}()

	return accepted
}

func dialHandshake(t *testing.T, pc net.PacketConn, raddr net.Addr, opts []ClientOption) *Conn {
	t.Helper()
	client, err := Client(pc, raddr, opts...)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

// handshakeWatcher reports, once armed, the first epoch 0 handshake record
// received.
type handshakeWatcher struct {
	net.PacketConn
	armed atomic.Bool
	seen  chan struct{}
	once  sync.Once
}

func (w *handshakeWatcher) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := w.PacketConn.ReadFrom(b)
	if n > recordlayer.FixedHeaderSize && w.armed.Load() &&
		protocol.ContentType(b[0]) == protocol.ContentTypeHandshake && b[3] == 0 && b[4] == 0 {
		w.once.Do(func() { close(w.seen) })
	}

	return n, addr, err
}

// captureClientHello returns the datagrams of a client's first flight.
func captureClientHello(t *testing.T, version protocol.Version) [][]byte {
	t.Helper()
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	client, err := Client(pc, sink.LocalAddr(), WithInsecureSkipVerify(true), WithMaxVersion(version))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.HandshakeContext(ctx) }()

	// A ClientHello may span several datagrams; the flight is sent at once.
	var flight [][]byte
	deadline := time.Now().Add(5 * time.Second)
	for {
		require.NoError(t, sink.SetReadDeadline(deadline))
		buf := make([]byte, 2048)
		n, _, err := sink.ReadFrom(buf)
		if err != nil {
			require.NotEmpty(t, flight)

			return flight
		}
		flight = append(flight, buf[:n])
		deadline = time.Now().Add(100 * time.Millisecond)
	}
}
