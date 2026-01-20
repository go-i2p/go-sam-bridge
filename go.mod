module github.com/go-i2p/go-sam-bridge

go 1.24.5

toolchain go1.24.12

require (
	github.com/go-i2p/common v0.1.0
	github.com/go-i2p/go-i2p v0.1.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/armon/circbuf v0.0.0-20190214190532-5111143e8da2 // indirect
	github.com/beevik/ntp v1.5.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-i2p/crypto v0.1.1-0.20251212210701-124dadb97cb7 // indirect
	github.com/go-i2p/elgamal v0.0.2 // indirect
	github.com/go-i2p/go-i2cp v0.1.0 // indirect
	github.com/go-i2p/go-streaming v0.0.0-20260120210156-9469386fc621 // indirect
	github.com/go-i2p/logger v0.1.0 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/samber/lo v1.52.0 // indirect
	github.com/samber/oops v1.20.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.step.sm/crypto v0.75.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
)

replace github.com/go-i2p/go-i2cp => ../../../github.com/go-i2p/go-i2cp

replace github.com/go-i2p/go-streaming => ../../../github.com/go-i2p/go-streaming

replace github.com/go-i2p/go-datagrams => ../../../github.com/go-i2p/go-datagrams
