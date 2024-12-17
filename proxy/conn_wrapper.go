package proxy

import (
	"bytes"
	"io"
	"net"
	"time"
)

var (
	_ net.Conn = (*connRewinder)(nil)
	_ net.Conn = (*innerConn)(nil)
)

type innerConn struct {
	reader io.Reader
	conn   net.Conn
}

func (ic *innerConn) LocalAddr() net.Addr {
	return ic.conn.LocalAddr()
}

func (ic *innerConn) RemoteAddr() net.Addr {
	return ic.conn.RemoteAddr()
}

func (ic *innerConn) SetDeadline(t time.Time) error {
	return ic.conn.SetDeadline(t)
}

func (ic *innerConn) SetReadDeadline(t time.Time) error {
	return ic.conn.SetReadDeadline(t)
}

func (ic *innerConn) SetWriteDeadline(t time.Time) error {
	return ic.conn.SetWriteDeadline(t)
}

func (ic *innerConn) Read(p []byte) (int, error) {
	return ic.reader.Read(p)
}

func (ic *innerConn) Write(p []byte) (int, error) {
	return ic.conn.Write(p)
}

func (ic *innerConn) Close() error {
	return ic.conn.Close()
}

// net.Conn with rewind functionality
type connRewinder struct {
	conn   net.Conn
	buffer *bytes.Buffer
}

func newConnRewinder(conn net.Conn) (*connRewinder, error) {
	return &connRewinder{
		conn:   conn,
		buffer: &bytes.Buffer{},
	}, nil
}

func (cw *connRewinder) LocalAddr() net.Addr {
	return cw.conn.LocalAddr()
}

func (cw *connRewinder) RemoteAddr() net.Addr {
	return cw.conn.RemoteAddr()
}

func (cw *connRewinder) SetDeadline(t time.Time) error {
	return cw.conn.SetDeadline(t)
}

func (cw *connRewinder) SetReadDeadline(t time.Time) error {
	return cw.conn.SetReadDeadline(t)
}

func (cw *connRewinder) SetWriteDeadline(t time.Time) error {
	return cw.conn.SetWriteDeadline(t)
}

func (cw *connRewinder) Read(p []byte) (int, error) {
	//reading data from connection
	n, err := cw.conn.Read(p)
	if err != nil {
		return n, err
	}

	// write read data from connection to buffer
	_, err = cw.buffer.Write(p[:n])
	if err != nil {
		return n, err
	}

	return n, nil
}

// rewinds read data
func (cw *connRewinder) Rewind() (net.Conn, error) {
	toReturn := &innerConn{
		reader: io.MultiReader(cw.buffer, cw.conn),
		conn:   cw.conn,
	}

	return toReturn, nil
}

func (cw *connRewinder) Write(p []byte) (int, error) {
	return cw.conn.Write(p)
}

func (cw *connRewinder) Close() error {
	return cw.conn.Close()
}
