package wgnet

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
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

type Device struct {
	dev  *device.Device
	tun  tun.Device
	tnet *netstack.Net
}

func NewDevice(c *Configuration) (*Device, error) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{c.MyIPv4}, c.DNS, c.MTU)
	if err != nil {
		return nil, fmt.Errorf("unable to create tunnel: %v", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wgnet: "))

	privkey, err := wgb64tohex(c.PrivateKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	pubkey, err := wgb64tohex(c.ServerPublicKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("invalid public key: %v", err)
	}

	ipcConfig := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d",
		privkey,
		pubkey,
		c.ServerEndpoint,
		c.PersistentKeepaliveInterval,
	)

	if err := dev.IpcSet(ipcConfig); err != nil {
		dev.Close()
		return nil, fmt.Errorf("unable to configure device: %v", err)
	}

	dev.Up()

	return &Device{
		dev:  dev,
		tun:  tun,
		tnet: tnet,
	}, nil
}

func (d *Device) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	return d.tnet.ListenTCP(addr)
}

func (d *Device) Close() error {
	d.dev.Close()
	return nil
}

func wgb64tohex(in string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return "", fmt.Errorf("unable to decode base64: %v", err)
	}

	if len(bytes) != 32 {
		return "", fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(bytes))
	}

	return hex.EncodeToString(bytes), nil
}
