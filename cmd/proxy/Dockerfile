FROM golang:1.22-alpine3.19 AS builder

RUN apk add --no-cache \
  build-base \
  make \
  curl

COPY . /workdir
WORKDIR /workdir

ENV CGO_CPPFLAGS="-D_FORTIFY_SOURCE=2 -fstack-protector-all"
ENV GOFLAGS="-buildmode=pie"

RUN make build-in-docker

FROM scratch
COPY --from=builder /workdir/_out/proxy /entrypoint

ENTRYPOINT ["/entrypoint"]
