package wgnet

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func generateKeys() (string, string, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub[:]), nil
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

func TestTwoPeerConnectivity(t *testing.T) {
	// 1. Generate keys
	serverPriv, serverPub, _ := generateKeys()
	clientPriv, clientPub, _ := generateKeys()

	serverIP := netip.MustParseAddr("10.0.0.1")
	clientIP := netip.MustParseAddr("10.0.0.2")

	// 2. Start Server
	serverConf := &Configuration{
		MyIPv4:     serverIP,
		PrivateKey: serverPriv,
		MTU:        1420,
	}
	serverDev, err := NewDevice(serverConf)
	if err != nil {
		t.Fatalf("failed to create server device: %v", err)
	}
	defer serverDev.Close()

	serverPort, err := getUDPPort(serverDev)
	if err != nil {
		t.Fatalf("failed to get server UDP port: %v", err)
	}

	// 3. Start Client
	clientConf := &Configuration{
		MyIPv4:          clientIP,
		PrivateKey:      clientPriv,
		ServerPublicKey: serverPub,
		ServerEndpoint:  fmt.Sprintf("127.0.0.1:%d", serverPort),
		MTU:             1420,
	}
	clientDev, err := NewDevice(clientConf)
	if err != nil {
		t.Fatalf("failed to create client device: %v", err)
	}
	defer clientDev.Close()

	// 4. Register Client on Server
	err = serverDev.dev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32",
		b64tohex_test(clientPub), clientIP.String()))
	if err != nil {
		t.Fatalf("failed to register client on server: %v", err)
	}

	// 5. Test TCP: Server listens, Client dials
	ln, err := serverDev.ListenTCP(net.TCPAddrFromAddrPort(netip.AddrPortFrom(serverIP, 8080)))
	if err != nil {
		t.Fatalf("server failed to listen: %v", err)
	}
	defer ln.Close()

	done := make(chan bool)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 5)
		io.ReadFull(conn, buf)
		if string(buf) == "HELLO" {
			conn.Write([]byte("WORLD"))
		}
		done <- true
	}()

	// Wait for handshake/setup
	time.Sleep(100 * time.Millisecond)

	clientConn, err := clientDev.DialTCP(net.TCPAddrFromAddrPort(netip.AddrPortFrom(serverIP, 8080)))
	if err != nil {
		t.Fatalf("client failed to dial: %v", err)
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HELLO"))
	buf := make([]byte, 5)
	io.ReadFull(clientConn, buf)

	if string(buf) != "WORLD" {
		t.Errorf("expected WORLD, got %s", string(buf))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("test timed out")
	}
}

// b64tohex_test is a helper because we need hex for IpcSet
func b64tohex_test(in string) string {
	b, _ := base64.StdEncoding.DecodeString(in)
	return fmt.Sprintf("%x", b)
}
