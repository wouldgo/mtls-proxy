SHELL := /bin/sh
OUT := $(shell pwd)/_out
BUILDARCH := $(shell uname -m)
GCC := $(OUT)/$(BUILDARCH)-linux-musl-cross/bin/$(BUILDARCH)-linux-musl-gcc
_PROXY_NAME := proxy
PROXY := $(OUT)/$(_PROXY_NAME)
IMAGE := ghcr.io/wouldgo/tls
VERSION := 0.1.2

proxy: install
	PEM_CREDS_FOLDER="_pems" \
	PEM_FULLCHAIN="ca.pem" \
	PEM_PRIVATE_KEY="private_key.pem" \
	CERTS_FOLDER="_fake_pki" \
	go run cmd/proxy/*.go

test: install
	rm -Rf $(OUT)/.coverage;
	go test -timeout 120s -cover -coverprofile=$(OUT)/.coverage -v ./...;
	go tool cover -html=$(OUT)/.coverage -o $(OUT)/coverage.html;

visualize-proxy: update
	go-callvis \
		-group pkg,type \
		-limit github.com/wouldgo/mtls-proxy \
		github.com/wouldgo/mtls-proxy/cmd/proxy

docker-push:
	docker push \
		$(IMAGE)-$(_PROXY_NAME):$(VERSION)

docker-build:
	docker build \
		-f cmd/proxy/Dockerfile \
		-t $(IMAGE)-$(_PROXY_NAME):$(VERSION) .

build-in-docker: install
	CGO_ENABLED=1 \
	CC_FOR_TARGET=$(GCC) \
	CC=$(GCC) \
	go build \
		-ldflags "-s -w -linkmode external -extldflags -static" \
		-trimpath \
		-a -o $(PROXY) cmd/proxy/*.go

build: install build-proxy

build-proxy:
	CGO_ENABLED=1 \
	CC_FOR_TARGET=$(GCC) \
	CC=$(GCC) \
	go build \
		-ldflags "-s -w -linkmode external -extldflags -static" \
		-trimpath \
		-a -o $(PROXY) cmd/proxy/*.go

update:
	go install github.com/ofabry/go-callvis@latest
	go mod tidy -v

install: musl
	go mod download

clean:
	rm -Rf $(OUT)/*
	mkdir -p $(OUT)
	touch $(OUT)/.keep

musl:
	if [ ! -d "$(OUT)/$(BUILDARCH)-linux-musl-cross" ]; then \
		(cd $(OUT); curl -LOk https://musl.cc/$(BUILDARCH)-linux-musl-cross.tgz) && \
		tar zxf $(OUT)/$(BUILDARCH)-linux-musl-cross.tgz -C $(OUT); \
	fi
