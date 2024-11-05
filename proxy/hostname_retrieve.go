package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

func getServerName(reader io.Reader) (string, error) {
	serverName, newReader, errHP := peekHTTPHost(reader)

	if errHP != nil {
		var errCH error
		serverName, _, errCH = peekClientHello(newReader)

		if errCH != nil {
			return "", errCH
		} else if serverName == "" {
			return "", errHP
		}
	}

	return serverName, nil
}

// takes the request host
func peekHTTPHost(reader io.Reader) (string, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	peekedData := io.TeeReader(reader, peekedBytes)
	newReader := io.MultiReader(peekedBytes, reader)

	teeReader := bufio.NewReader(peekedData)
	r, err := http.ReadRequest(teeReader)
	if err != nil {
		return "", newReader, fmt.Errorf("reading http request in error: %w", err)
	}

	return r.Host, newReader, nil
}

// takes server name from ClientHello SNI
func peekClientHello(reader io.Reader) (string, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	peekedData := io.TeeReader(reader, peekedBytes)
	newReader := io.MultiReader(peekedBytes, reader)

	hello, err := readClientHello(peekedData)
	if err != nil {
		return "", newReader, err
	}

	return hello.ServerName, newReader, nil
}

// client hello information
func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	config := &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}

	tlsConn := tls.Server(readOnlyConn{reader}, config)
	err := tlsConn.HandshakeContext(context.TODO())

	if hello == nil {
		return nil, fmt.Errorf("client hello info getting in error: %w", err)
	}

	return hello, nil
}
