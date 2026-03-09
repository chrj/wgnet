// Package wgnet provides a thin frontend for user-space VPN connections using the Go
// wireguard implementation running on the gVisor user-space network stack
package wgnet

import (
	"context"
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

func NewDefaultConfiguration() *Configuration {
	return &Configuration{
		DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		MTU: 1420,

		PersistentKeepaliveInterval: 25,
	}
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

	privkey, err := b64tohex(c.PrivateKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	var ipcConfig string

	if c.ServerPublicKey != "" {
		// Peer mode

		pubkey, err := b64tohex(c.ServerPublicKey)
		if err != nil {
			dev.Close()
			return nil, fmt.Errorf("invalid server public key: %v", err)
		}

		ipcConfig = fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d\n",
			privkey,
			pubkey,
			c.ServerEndpoint,
			c.PersistentKeepaliveInterval,
		)

	} else {
		// Server mode

		ipcConfig = fmt.Sprintf("private_key=%s\nreplace_peers=true\n",
			privkey,
		)

	}

	if err := dev.IpcSet(ipcConfig); err != nil {
		dev.Close()
		return nil, fmt.Errorf("unable to configure device: %v", err)
	}

	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("unable to bring up WireGuard device: %v", err)
	}

	return &Device{
		dev:  dev,
		tun:  tun,
		tnet: tnet,
	}, nil
}

func (d *Device) Dial(network, address string) (net.Conn, error) {
	return d.tnet.Dial(network, address)
}

func (d *Device) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tnet.DialContext(ctx, network, address)
}

func (d *Device) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	return d.tnet.ListenTCP(addr)
}

func (d *Device) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	return d.tnet.DialTCP(addr)
}

func (d *Device) AddPeer(publicKey string, clientIP netip.Addr) error {
	hexkey, err := b64tohex(publicKey)
	if err != nil {
		return fmt.Errorf("unable to convert peer public key to hex: %v", err)
	}
	err = d.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\nallowed_ip=%s/32",
		hexkey,
		clientIP.String(),
	))
	if err != nil {
		return fmt.Errorf("failed to register client on server: %v", err)
	}
	return nil
}

func (d *Device) Close() error {
	d.dev.Close()
	return nil
}
