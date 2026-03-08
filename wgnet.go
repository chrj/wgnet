package wgnet

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Configuration struct {
	MyIPv4     netip.Addr
	PrivateKey string
	DNS        []netip.Addr
	MTU        int

	ServerPublicKey string
	ServerEndpoint  string

	PersistentKeepaliveInterval int
}

func (c *Configuration) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{c.MyIPv4}, c.DNS, c.MTU)
	if err != nil {
		return nil, fmt.Errorf("unable to create tunnel: %v", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, "wgnet: "))

	privkey, err := b64tohex(c.PrivateKey)
	if err != nil {
		return nil, err
	}

	pubkey, err := b64tohex(c.ServerPublicKey)
	if err != nil {
		return nil, err
	}

	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d",
		privkey,
		pubkey,
		c.ServerEndpoint,
		c.PersistentKeepaliveInterval,
	)); err != nil {
		return nil, fmt.Errorf("unable to configure device: %v", err)
	}

	dev.Up()

	listener, err := tnet.ListenTCP(addr)
	if err != nil {
		return nil, fmt.Errorf("listen error: %v", err)
	}

	return listener, nil

}

func b64tohex(in string) (string, error) {

	bytes, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return "", fmt.Errorf("unable to decode base64: %v", err)
	}

	return hex.EncodeToString(bytes), nil
}
