package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func newHTTPClient() (*http.Client, error) {
	proxyURL, err := url.Parse("http://localhost:3000")
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	return client, nil
}

func main() {
	httpClient, err := newHTTPClient()
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	c, response, err := websocket.Dial(ctx, "http://echo.websocket.org", &websocket.DialOptions{
		HTTPClient: httpClient,
	})
	if err != nil {
		panic(err)
	}
	defer c.CloseNow()

	fmt.Printf("---- %++v", response)

	go func() {

		for {
			fmt.Println("reading data")
			msg, bytes, err := c.Read(ctx)
			if err != nil {
				panic(err)
			}
			fmt.Printf("------------\r\n")
			fmt.Printf("bytes:   %s\r\n", bytes)
			fmt.Printf("message: %s\r\n", msg)
			fmt.Printf("------------\r\n")
		}
	}()

	err = wsjson.Write(ctx, c, "hello")
	if err != nil {
		panic(err)
	}

	<-ctx.Done()
	c.Close(websocket.StatusNormalClosure, "closing")
}
