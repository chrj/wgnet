package wgnet

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PeerStat is the live state of one configured peer.
//
// It carries no key material other than the peer's own public key. The device's
// private key and any preshared key stay inside the device.
type PeerStat struct {
	// PublicKey identifies the peer, base64 encoded as the WireGuard tools print it.
	PublicKey string
	// Endpoint is the peer's current UDP address. It is empty until the device
	// has learned one.
	Endpoint string
	// LastHandshake is when the peer last completed a handshake. It is the zero
	// time when the peer has never completed one, which a caller wants to tell
	// apart from one that completed a long time ago.
	LastHandshake time.Time
	// TxBytes and RxBytes count traffic to and from the peer since the device started.
	TxBytes uint64
	RxBytes uint64
}

// Age reports how long ago the peer completed its last handshake. The second
// return is false when the peer has never completed one.
func (p PeerStat) Age() (time.Duration, bool) {
	if p.LastHandshake.IsZero() {
		return 0, false
	}
	return time.Since(p.LastHandshake), true
}

// Peers reports the live state of every configured peer.
//
// WireGuard rekeys a busy tunnel every couple of minutes, so a handshake that is
// suddenly many minutes old says the path to that peer is down. The device
// itself keeps accepting writes either way, so this is the signal that separates
// a dead tunnel from a slow answer at the other end.
func (d *Device) Peers() ([]PeerStat, error) {
	ipc, err := d.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("unable to read device state: %w", err)
	}
	return parsePeers(ipc)
}

// stamp is a peer's handshake time as the IPC reports it, in two fields.
type stamp struct{ sec, nsec int64 }

// parsePeers reads the peer sections of an IPC config body. A peer starts at a
// public_key line. Everything before the first one describes the device itself
// and is skipped, which is what keeps the private key out of the result.
func parsePeers(ipc string) ([]PeerStat, error) {
	var (
		peers  []PeerStat
		stamps []stamp
	)

	for _, line := range strings.Split(ipc, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}

		if key == "public_key" {
			b64, err := hextob64(value)
			if err != nil {
				return nil, fmt.Errorf("invalid peer public key: %w", err)
			}
			peers = append(peers, PeerStat{PublicKey: b64})
			stamps = append(stamps, stamp{})
			continue
		}
		if len(peers) == 0 {
			continue // still inside the device's own section
		}

		var err error
		p, s := &peers[len(peers)-1], &stamps[len(stamps)-1]
		switch key {
		case "endpoint":
			p.Endpoint = value
		case "last_handshake_time_sec":
			s.sec, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			s.nsec, err = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			p.TxBytes, err = strconv.ParseUint(value, 10, 64)
		case "rx_bytes":
			p.RxBytes, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid %s value %q: %w", key, value, err)
		}
	}

	// A peer that has never completed a handshake reports zero in both fields,
	// which must stay the zero time rather than becoming the Unix epoch.
	for i, s := range stamps {
		if s.sec != 0 || s.nsec != 0 {
			peers[i].LastHandshake = time.Unix(s.sec, s.nsec)
		}
	}
	return peers, nil
}
