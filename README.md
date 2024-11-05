# mTLS proxy

```sh
HTTPS_PROXY=127.0.0.1:3000 curl -x 127.0.0.1:3000 -vvv --cacert ./_fake_pki/_ca/certificate.pem https://google.com
```
```sh
websocat -t --ws-c-uri=wss://echo.websocket.org/ - ws-c:cmd:'socat - proxy:127.0.0.1:echo.websocket.org:443,proxyport=3000'
```



# iptables

## Add

```sh
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1000 -j REDIRECT --to-ports 3000
```

## Remove

```sh
iptables -L
```

```sh
sudo iptables -t nat -D OUTPUT <num>
```
