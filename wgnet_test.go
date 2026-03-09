package wgnet

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestPeerConnectivity(t *testing.T) {

	// Spin up the server

	serverKey := RandomKey()

	serverConf := NewDefaultConfiguration()
	serverConf.PrivateKey = serverKey.Private()
	serverConf.MyIPv4 = netip.MustParseAddr("10.0.0.1")

	serverDev, err := NewDevice(serverConf)
	if err != nil {
		t.Fatalf("failed to create server device: %v", err)
	}
	defer serverDev.Close()

	serverPort, err := getUDPPort(serverDev)
	if err != nil {
		t.Fatalf("unable to get server port: %v", err)
	}

	// Spin up the client

	clientKey := RandomKey()
	clientConf := NewDefaultConfiguration()
	clientConf.PrivateKey = clientKey.Private()
	clientConf.ServerPublicKey = serverKey.Public()
	clientConf.ServerEndpoint = fmt.Sprintf("127.0.0.1:%d", serverPort)
	clientConf.MyIPv4 = netip.MustParseAddr("10.0.0.2")

	clientDev, err := NewDevice(clientConf)
	if err != nil {
		t.Fatalf("failed to create client device: %v", err)
	}
	defer clientDev.Close()

	// Register Client on Server

	if err := serverDev.AddPeer(clientKey.Public(), clientConf.MyIPv4); err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	// Configure the address for the test server

	echoServerAddr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(serverConf.MyIPv4, 8080))

	// Configure listener for the test server

	ln, err := serverDev.ListenTCP(echoServerAddr)
	if err != nil {
		t.Fatalf("server failed to listen: %v", err)
	}
	defer ln.Close()

	// Spin up echoServer

	go echoServer(ln)

	// Call the echoServer from the client device

	clientConn, err := clientDev.DialTCP(echoServerAddr)
	if err != nil {
		t.Fatalf("client failed to dial: %v", err)
	}
	defer clientConn.Close()

	clientConn.Write([]byte("testing"))
	buf := make([]byte, 7)
	io.ReadFull(clientConn, buf)
	clientConn.Close()

	if string(buf) != "testing" {
		t.Errorf("expected testing, got %s", string(buf))
	}

}

func getUDPPort(d *Device) (int, error) {
	config, err := d.dev.IpcGet()
	if err != nil {
		return 0, err
	}

	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			var port int
			_, err := fmt.Sscanf(line, "listen_port=%d", &port)
			return port, err
		}
	}
	return 0, fmt.Errorf("listen_port not found in IPC config")
}

func echoServer(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if operr, ok := err.(*net.OpError); ok && operr.Err.Error() == "endpoint is in invalid state" {
				// Listener was shut down
				return
			}
			log.Printf("Failed to accept connection: %#v\n", err)
			return
		}

		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}(conn)
	}
}
