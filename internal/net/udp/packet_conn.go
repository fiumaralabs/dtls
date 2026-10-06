// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package udp implements DTLS specific UDP networking primitives.
// NOTE: this package is an adaptation of pion/transport/udp that allows for
// routing datagrams based on identifiers other than the remote address. The
// primary use case for this functionality is routing based on DTLS connection
// IDs. In order to allow for consumers of this package to treat connections as
// generic net.PacketConn, routing and identifier establishment is based on
// custom introspection of datagrams, rather than direct intervention by
// consumers. If possible, the updates made in this repository will be reflected
// back upstream. If not, it is likely that this will be moved to a public
// package in this repository.
//
// This package was migrated from pion/transport/udp at
// https://github.com/pion/transport/commit/6890c795c807a617c054149eee40a69d7fdfbfdb
package udp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	idtlsnet "github.com/pion/dtls/v4/internal/net"
	dtlsnet "github.com/pion/dtls/v4/pkg/net"
	"github.com/pion/transport/v5/deadline"
)

const (
	defaultReceiveBufferSize = 8192
	defaultListenBacklog     = 128 // same as Linux default
)

// Typed errors.
var (
	ErrClosedListener      = dtlserrors.ErrUDPClosedListener
	ErrListenQueueExceeded = dtlserrors.ErrUDPListenQueueExceeded
	ErrCIDInUse            = errors.New("connection ID already belongs to another connection")
	ErrAddressInUse        = errors.New("remote address already belongs to another connection")
)

type addressKey struct {
	network string
	address string
}

func keyForAddress(addr net.Addr) addressKey {
	return addressKey{network: addr.Network(), address: addr.String()}
}

// listener augments a connection-oriented Listener over a UDP PacketConn.
type listener struct {
	pConn net.PacketConn

	accepting         atomic.Bool
	acceptMu          sync.Mutex // serializes new-connection admission with shutdown's queue drain
	acceptCh          chan *PacketConn
	doneCh            chan struct{}
	doneOnce          sync.Once
	acceptFilter      func([]byte) bool
	datagramRouter    func([]byte) (string, bool)
	classifyRecord    func([]byte) (epochZero bool, clientRandom []byte)
	receiveBufferSize int
	backlog           int

	routesMu  sync.RWMutex
	cids      map[string]*PacketConn
	addresses map[addressKey]*PacketConn
	// pending holds connections handshaking on the address of an
	// established connection, which keeps the address until they complete.
	pending map[addressKey]*PacketConn

	nConns atomic.Int64
	connWG sync.WaitGroup

	readWG   sync.WaitGroup
	errClose atomic.Value // error

	readDoneCh chan struct{}
	errRead    atomic.Value // error
}

// Accept waits for and returns the next connection to the listener.
func (l *listener) Accept() (net.PacketConn, net.Addr, error) {
	select {
	case c := <-l.acceptCh:
		l.connWG.Add(1)

		return c, c.raddr.Load().(net.Addr), nil //nolint:forcetypeassert

	case <-l.readDoneCh:
		err, _ := l.errRead.Load().(error)

		return nil, nil, err

	case <-l.doneCh:
		return nil, nil, ErrClosedListener
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *listener) Close() error {
	var err error
	l.doneOnce.Do(func() {
		l.accepting.Store(false)
		close(l.doneCh)

		// Wait for in-flight admissions before draining the queue.
		l.acceptMu.Lock()

		// Close unaccepted connections
		for {
			select {
			case c := <-l.acceptCh:
				if !c.closing.Swap(true) {
					c.listener.nConns.Add(-1)
					close(c.doneCh)
					l.removeRoutes(c)
					_ = c.buffer.Close()
				}

				continue
			default:
			}

			break
		}

		nConns := l.nConns.Load()
		l.acceptMu.Unlock()

		l.connWG.Done()

		if nConns == 0 {
			// Wait if this is the final connection.
			l.readWG.Wait()
			if errClose, ok := l.errClose.Load().(error); ok {
				err = errClose
			}
		} else {
			err = nil
		}
	})

	return err
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.pConn.LocalAddr()
}

// ListenerOption configures a packet listener.
type ListenerOption func(*listener)

// WithBacklog sets the maximum number of pending connections.
func WithBacklog(backlog int) ListenerOption {
	return func(l *listener) {
		if backlog != 0 {
			l.backlog = backlog
		}
	}
}

// WithAcceptFilter sets the filter used to admit new connections.
func WithAcceptFilter(filter func([]byte) bool) ListenerOption {
	return func(l *listener) {
		l.acceptFilter = filter
	}
}

// WithDatagramRouter sets the function used to route incoming datagrams.
func WithDatagramRouter(router func([]byte) (string, bool)) ListenerOption {
	return func(l *listener) {
		l.datagramRouter = router
	}
}

// WithNewHandshakeOnAddress lets an epoch 0 ClientHello from the address of
// an established connection start a new connection (RFC 6347 Section 4.2.8).
// classify reports whether the first record of a datagram has epoch 0 and,
// if it is a ClientHello, its random.
func WithNewHandshakeOnAddress(classify func([]byte) (epochZero bool, clientRandom []byte)) ListenerOption {
	return func(l *listener) {
		l.classifyRecord = classify
	}
}

// WithReceiveBufferSize sets the size of the buffer used to read incoming datagrams.
func WithReceiveBufferSize(size int) ListenerOption {
	return func(l *listener) {
		if size > 0 {
			l.receiveBufferSize = size
		}
	}
}

// Listen creates a new listener over conn.
func Listen(conn net.PacketConn, opts ...ListenerOption) dtlsnet.PacketListener {
	packetListener := &listener{
		pConn:             conn,
		backlog:           defaultListenBacklog,
		receiveBufferSize: defaultReceiveBufferSize,
		doneCh:            make(chan struct{}),
		readDoneCh:        make(chan struct{}),
		cids:              make(map[string]*PacketConn),
		addresses:         make(map[addressKey]*PacketConn),
		pending:           make(map[addressKey]*PacketConn),
	}
	for _, opt := range opts {
		opt(packetListener)
	}

	packetListener.acceptCh = make(chan *PacketConn, packetListener.backlog)
	packetListener.accepting.Store(true)

	packetListener.connWG.Add(1)
	packetListener.readWG.Add(2) // wait readLoop and Close execution routine

	go packetListener.readLoop()
	go func() {
		packetListener.connWG.Wait()
		if err := packetListener.pConn.Close(); err != nil {
			packetListener.errClose.Store(err)
		}
		packetListener.readWG.Done()
	}()

	return packetListener
}

// readLoop dispatches packets to the proper connection, creating a new one if
// necessary, until all connections are closed.
func (l *listener) readLoop() {
	defer l.readWG.Done()
	defer close(l.readDoneCh)

	buf := make([]byte, l.receiveBufferSize)

	for {
		n, raddr, err := l.pConn.ReadFrom(buf)
		if idtlsnet.IsShortBuffer(err) {
			if n == 0 || raddr == nil {
				continue
			}
		} else if err != nil {
			l.errRead.Store(err)

			return
		}
		conn, also, ok, err := l.getConn(raddr, buf[:n])
		if err != nil {
			continue
		}
		if ok {
			_, _ = conn.buffer.WriteTo(buf[:n], raddr)
		}
		if also != nil {
			_, _ = also.buffer.WriteTo(buf[:n], raddr)
		}
	}
}

// getConn gets an existing connection or creates a new one. If the second
// connection is not nil, it receives the datagram too.
func (l *listener) getConn(raddr net.Addr, buf []byte) (*PacketConn, *PacketConn, bool, error) { //nolint:cyclop
	if l.datagramRouter != nil {
		if cid, ok := l.datagramRouter(buf); ok {
			l.routesMu.RLock()
			conn := l.cids[cid]
			l.routesMu.RUnlock()
			if conn == nil || conn.closing.Load() {
				return nil, nil, false, nil
			}

			return conn, nil, true, nil
		}
	}

	key := keyForAddress(raddr)
	l.routesMu.RLock()
	conn, pending := l.addressRoutesLocked(key)
	l.routesMu.RUnlock()
	if conn != nil {
		if conn.closing.Load() {
			return conn, nil, false, nil
		}
		if l.classifyRecord != nil && conn.established.Load() {
			return l.routeEstablished(conn, pending, raddr, buf)
		}

		return conn, nil, true, nil
	}
	if !l.accepting.Load() {
		return nil, nil, false, ErrClosedListener
	}
	if l.acceptFilter != nil && !l.acceptFilter(buf) {
		return nil, nil, false, nil
	}

	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()
	if !l.accepting.Load() {
		return nil, nil, false, ErrClosedListener
	}
	l.routesMu.Lock()
	defer l.routesMu.Unlock()
	if conn, _ = l.addressRoutesLocked(key); conn != nil {
		return conn, nil, !conn.closing.Load(), nil
	}
	conn, err := l.admitLocked(raddr)
	if err != nil {
		return nil, nil, false, err
	}
	l.addresses[key] = conn

	return conn, nil, true, nil
}

// addressRoutesLocked returns the connection routed by key and the pending
// connection waiting to replace it. A pending connection whose predecessor
// has closed is returned as the routed one. It requires routesMu.
func (l *listener) addressRoutesLocked(key addressKey) (conn, pending *PacketConn) {
	conn, pending = l.addresses[key], l.pending[key]
	if conn == nil {
		return pending, nil
	}

	return conn, pending
}

// admitLocked queues a new connection for Accept. It requires acceptMu and
// routesMu.
func (l *listener) admitLocked(raddr net.Addr) (*PacketConn, error) {
	conn := l.newPacketConn(raddr)
	l.nConns.Add(1)
	select {
	case l.acceptCh <- conn:
		return conn, nil
	default:
		l.nConns.Add(-1)
		_ = conn.buffer.Close()

		return nil, ErrListenQueueExceeded
	}
}

// routeEstablished routes a datagram from the address of an established
// connection. An epoch 0 ClientHello starts a pending connection for a new
// handshake (RFC 6347 Section 4.2.8). The established connection keeps the
// address until that handshake completes, so a ClientHello from a spoofed
// address cannot take over the association. Meanwhile epoch 0 records go to
// the pending connection only and later epochs to both: each discards the
// records it cannot authenticate.
//
// A ClientHello with another random replaces the pending connection, so an
// abandoned or spoofed attempt cannot hold the address until it times out.
// Retransmissions and the ClientHello answering a cookie keep the random.
func (l *listener) routeEstablished(conn, pending *PacketConn, raddr net.Addr, buf []byte) (*PacketConn, *PacketConn, bool, error) {
	epochZero, random := l.classifyRecord(buf)
	if pending != nil && pending.closing.Load() {
		pending = nil
	}
	if random != nil && (pending == nil || pending.clientRandom != string(random)) {
		var err error
		if pending, err = l.admitPending(raddr, string(random)); err != nil {
			return nil, nil, false, err
		}
	}
	switch {
	case pending == nil:
		return conn, nil, true, nil
	case epochZero:
		return pending, nil, true, nil
	default:
		return conn, pending, true, nil
	}
}

// admitPending queues a pending connection for a ClientHello with random. A
// replaced pending connection is detached: it stops reading and writing, so
// its handshake fails.
func (l *listener) admitPending(raddr net.Addr, random string) (*PacketConn, error) {
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()
	if !l.accepting.Load() {
		return nil, ErrClosedListener
	}
	l.routesMu.Lock()
	defer l.routesMu.Unlock()
	key := keyForAddress(raddr)
	previous := l.pending[key]
	if previous != nil && !previous.closing.Load() && previous.clientRandom == random {
		return previous, nil
	}
	conn, err := l.admitLocked(raddr)
	if err != nil {
		return nil, err
	}
	conn.clientRandom = random
	l.pending[key] = conn
	if previous != nil {
		previous.detached.Store(true)
		_ = previous.buffer.Close()
	}

	return conn, nil
}

// PacketConn is a net.PacketConn implementation with explicit CID and address routing.
type PacketConn struct {
	listener *listener

	closing     atomic.Bool
	detached    atomic.Bool // replaced while pending
	established atomic.Bool
	raddr       atomic.Value // net.Addr

	cids    map[string]struct{}
	address addressKey
	// clientRandom is the ClientHello random of a pending connection.
	clientRandom string

	buffer *idtlsnet.PacketBuffer

	doneCh chan struct{}

	writeDeadline *deadline.Deadline
}

// newPacketConn constructs a new PacketConn.
func (l *listener) newPacketConn(raddr net.Addr) *PacketConn {
	res := &PacketConn{
		listener:      l,
		cids:          make(map[string]struct{}),
		address:       keyForAddress(raddr),
		buffer:        idtlsnet.NewPacketBuffer(),
		doneCh:        make(chan struct{}),
		writeDeadline: deadline.New(),
	}
	res.raddr.Store(raddr)

	return res
}

// RegisterCID replaces all inbound CID aliases with cid.
func (c *PacketConn) RegisterCID(cid []byte) error {
	c.listener.routesMu.Lock()
	defer c.listener.routesMu.Unlock()
	if c.closing.Load() {
		return io.EOF
	}
	key := string(cid)
	if owner := c.listener.cids[key]; owner != nil && owner != c {
		return ErrCIDInUse
	}
	c.removeCIDsLocked()
	if key != "" {
		c.listener.cids[key] = c
		c.cids[key] = struct{}{}
	}

	return nil
}

// RegisterCIDs atomically reserves additional inbound CID aliases.
func (c *PacketConn) RegisterCIDs(cids [][]byte) error {
	c.listener.routesMu.Lock()
	defer c.listener.routesMu.Unlock()
	if c.closing.Load() {
		return io.EOF
	}
	for _, cid := range cids {
		if owner := c.listener.cids[string(cid)]; owner != nil && owner != c {
			return ErrCIDInUse
		}
	}
	for _, cid := range cids {
		if len(cid) != 0 {
			key := string(cid)
			c.listener.cids[key] = c
			c.cids[key] = struct{}{}
		}
	}

	return nil
}

// UnregisterCID removes an inbound alias owned by this connection.
func (c *PacketConn) UnregisterCID(cid []byte) {
	c.listener.routesMu.Lock()
	defer c.listener.routesMu.Unlock()
	key := string(cid)
	if c.listener.cids[key] == c {
		delete(c.listener.cids, key)
	}
	delete(c.cids, key)
}

// removeCIDsLocked requires listener.routesMu to be held.
func (c *PacketConn) removeCIDsLocked() {
	for key := range c.cids {
		if c.listener.cids[key] == c {
			delete(c.listener.cids, key)
		}
	}
	clear(c.cids)
}

// SetRemoteAddr updates address routing after the migration policy accepts a path.
func (c *PacketConn) SetRemoteAddr(addr net.Addr) error {
	c.listener.routesMu.Lock()
	defer c.listener.routesMu.Unlock()
	if c.closing.Load() {
		return io.EOF
	}
	key := keyForAddress(addr)
	if owner := c.listener.addresses[key]; owner != nil && owner != c {
		return ErrAddressInUse
	}
	if c.listener.addresses[c.address] == c {
		delete(c.listener.addresses, c.address)
	}
	c.listener.addresses[key] = c
	c.address = key
	c.raddr.Store(addr)

	return nil
}

func (l *listener) removeRoutes(c *PacketConn) {
	l.routesMu.Lock()
	defer l.routesMu.Unlock()
	c.removeCIDsLocked()
	if l.addresses[c.address] == c {
		delete(l.addresses, c.address)
	}
	if l.pending[c.address] == c {
		delete(l.pending, c.address)
	}
}

// HandshakeComplete marks c as established. A pending connection then takes
// over its address and the connection it replaces is closed: after a
// verified Finished, RFC 6347 Section 4.2.8 requires abandoning the previous
// association.
func (c *PacketConn) HandshakeComplete() {
	c.established.Store(true)
	l := c.listener
	l.routesMu.Lock()
	if l.pending[c.address] != c {
		l.routesMu.Unlock()

		return
	}
	delete(l.pending, c.address)
	previous := l.addresses[c.address]
	l.addresses[c.address] = c
	l.routesMu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
}

// ReadFrom reads a single packet payload and its associated remote address from
// the underlying buffer.
func (c *PacketConn) ReadFrom(buff []byte) (int, net.Addr, error) {
	return c.buffer.ReadFrom(buff)
}

// WriteTo writes len(payload) bytes from payload to the specified address.
func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (n int, err error) {
	if c.closing.Load() || c.detached.Load() {
		return 0, io.EOF
	}

	select {
	case <-c.writeDeadline.Done():
		return 0, context.DeadlineExceeded
	default:
	}

	return c.listener.pConn.WriteTo(payload, addr)
}

// Close closes the conn and releases any Read calls.
func (c *PacketConn) Close() error {
	var err error
	if !c.closing.Swap(true) { //nolint:nestif
		c.listener.connWG.Done()
		close(c.doneCh)
		c.listener.removeRoutes(c)

		nConns := c.listener.nConns.Add(-1)

		if nConns == 0 && !c.listener.accepting.Load() {
			// Wait if this is the final connection
			c.listener.readWG.Wait()
			if errClose, ok := c.listener.errClose.Load().(error); ok {
				err = errClose
			}
		} else {
			err = nil
		}

		if errBuf := c.buffer.Close(); errBuf != nil && err == nil {
			err = errBuf
		}
	}

	return err
}

// LocalAddr implements net.PacketConn.LocalAddr.
func (c *PacketConn) LocalAddr() net.Addr {
	return c.listener.pConn.LocalAddr()
}

// SetDeadline implements net.PacketConn.SetDeadline.
func (c *PacketConn) SetDeadline(t time.Time) error {
	c.writeDeadline.Set(t)

	return c.SetReadDeadline(t)
}

// SetReadDeadline implements net.PacketConn.SetReadDeadline.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	return c.buffer.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn.SetWriteDeadline.
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	// Write deadline of underlying connection should not be changed
	// since the connection can be shared.
	return nil
}
