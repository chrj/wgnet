package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"

	"github.com/chrj/wgnet"
)

func handler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(rw, "Hello world\n")
}

func main() {

	wgconf := wgnet.NewDefaultConfiguration()
	wgconf.MyIPv4 = netip.MustParseAddr("10.42.0.60")
	wgconf.PrivateKey = "<output of wg genkey>"
	wgconf.ServerEndpoint = "<ip address>:51820"
	wgconf.ServerPublicKey = "<output of wg pubkey>"

	dev, err := wgnet.NewDevice(wgconf)
	if err != nil {
		log.Fatalf("unable to create device: %v", err)
	}
	defer dev.Close()

	addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("10.42.0.60:80"))

	ln, err := dev.ListenTCP(addr)
	if err != nil {
		log.Fatalf("unable to listen: %v", err)
	}

	log.Printf("Listening on %s", addr.String())
	log.Fatal(http.Serve(ln, http.HandlerFunc(handler)))

}
