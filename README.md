# mTLS proxy

```sh
HTTPS_PROXY=127.0.0.1:3000 curl -x 127.0.0.1:3000 -vvv --cacert ./_fake_pki/_ca/certificate.pem https://google.com
```
```sh
HTTPS_PROXY=127.0.0.1:3000 curl -x 127.0.0.1:3000 --cacert ./_fake_pki/_ca/certificate.pem --http1.1 -i -N -H 'Sec-Websocket-Version: 13' -H 'Sec-Websocket-Key: QUo86XL2bHszCCpigvKqHg==' -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Host: echo.websocket.org" -H "Origin: https://www.websocket.org" https://echo.websocket.org
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
