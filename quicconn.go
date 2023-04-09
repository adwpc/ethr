package main

import (
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

type QuicStreamConn struct {
	stream quic.Stream
	local  net.Addr
	remote net.Addr
}

func (q QuicStreamConn) Read(b []byte) (n int, err error) {
	return q.stream.Read(b)
}

func (q QuicStreamConn) Write(b []byte) (n int, err error) {
	return q.stream.Write(b)
}

func (q QuicStreamConn) Close() error {
	return q.stream.Close()
}

func (q QuicStreamConn) LocalAddr() net.Addr {
	return q.local
}

func (q QuicStreamConn) RemoteAddr() net.Addr {
	return q.remote
}

func (q QuicStreamConn) SetDeadline(t time.Time) error {
	return q.stream.SetDeadline(t)
}

func (q QuicStreamConn) SetReadDeadline(t time.Time) error {
	return q.stream.SetReadDeadline(t)
}

func (q QuicStreamConn) SetWriteDeadline(t time.Time) error {
	return q.stream.SetWriteDeadline(t)
}
