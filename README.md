# wgnet

[![Go Reference](https://pkg.go.dev/badge/github.com/chrj/wgnet.svg)](https://pkg.go.dev/github.com/chrj/wgnet)
[![Go Report Card](https://goreportcard.com/badge/github.com/chrj/wgnet)](https://goreportcard.com/report/github.com/chrj/wgnet)

`wgnet` provides a thin frontend for user-space VPN connections using the [Go WireGuard implementation](https://git.zx2c4.com/wireguard-go/about/) running on the [gVisor user-space network stack](https://github.com/google/gvisor).

It allows Go applications to dial and listen on a WireGuard network entirely in user-space, without requiring root privileges or special kernel modules.

## Installation

```bash
go get github.com/chrj/wgnet
```

## Quick Start

### Client: Dialing over WireGuard

```go
package main

import (
	"io"
	"log"
	"net/netip"
	"os"

	"github.com/chrj/wgnet"
)

func main() {
	// 1. Configure the device
	cfg := wgnet.NewDefaultConfiguration()
	cfg.MyIPv4 = netip.MustParseAddr("10.42.0.2")
	cfg.PrivateKey = "your-private-key"
	cfg.ServerPublicKey = "server-public-key"
	cfg.ServerEndpoint = "1.2.3.4:51820"

	// 2. Create the device
	dev, err := wgnet.NewDevice(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	// 3. Use the device to dial a connection over the VPN
	conn, err := dev.Dial("tcp", "10.42.0.1:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Use conn like a regular net.Conn
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: 10.42.0.1\r\n\r\n")
	io.Copy(os.Stdout, conn)
}
```

### Server: Listening over WireGuard

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"

	"github.com/chrj/wgnet"
)

func main() {
	cfg := wgnet.NewDefaultConfiguration()
	cfg.MyIPv4 = netip.MustParseAddr("10.42.0.2")
	cfg.PrivateKey = "your-private-key"
	cfg.ServerPublicKey = "server-public-key"
	cfg.ServerEndpoint = "1.2.3.4:51820"

	dev, err := wgnet.NewDevice(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	// Listen on the VPN interface
	ln, err := dev.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP("10.42.0.2"),
		Port: 8080,
	})
	if err != nil {
		log.Fatal(err)
	}

	http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from WireGuard!")
	}))
}
```

## License

MIT - See [LICENSE](LICENSE) for details.
