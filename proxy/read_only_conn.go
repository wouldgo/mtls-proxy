package proxy

import (
	"io"
	"net"
	"time"
)

var _ net.Conn = (*readOnlyConn)(nil)

// Handshake method of tls.Server will not write any data to the underlying connection.
type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(_ []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(_ time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(_ time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(_ time.Time) error { return nil }
