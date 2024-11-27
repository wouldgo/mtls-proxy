package proxy

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

// net.Conn with rewind functionality
type connRewinder struct {
	rewindable bool
	conn       net.Conn
	buffer     *bytes.Buffer
}

var _ net.Conn = (*connRewinder)(nil)

func newConnRewinder(conn net.Conn) (*connRewinder, error) {
	return &connRewinder{
		rewindable: true,
		conn:       conn,
		buffer:     &bytes.Buffer{},
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
	//reading data from buffer, if present
	if cw.buffer.Len() > 0 {
		return cw.buffer.Read(p)
	}

	//reading data from connection
	n, err := cw.conn.Read(p)
	if err != nil {
		return n, err
	}

	if cw.rewindable {
		// write read data from connection to buffer
		cw.buffer.Write(p[:n])
		return n, nil
	}

	return n, err
}

// rewinds read data
func (cw *connRewinder) Rewind() error {
	if !cw.rewindable {
		return fmt.Errorf("no more rewind supported")
	}

	cw.buffer = bytes.NewBuffer(cw.buffer.Bytes())
	cw.rewindable = !cw.rewindable
	return nil
}

func (cw *connRewinder) Write(p []byte) (int, error) {
	return cw.conn.Write(p)
}

func (cw *connRewinder) Close() error {
	return cw.conn.Close()
}
