package wgnet

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The device's own secrets, as IpcGet prints them. A peer listing must never
// carry these back to the caller.
const (
	testPrivateHex   = "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
	testPresharedHex = "1111111111111111111111111111111111111111111111111111111111111111"
)

// ipcFixture builds an IpcGet body for the given peer sections.
func ipcFixture(peers ...string) string {
	head := "private_key=" + testPrivateHex + "\nlisten_port=51820\nfwmark=0\n"
	return head + strings.Join(peers, "") + "errno=0\n"
}

// peerSection renders one peer the way IpcGet does, keyed by a base64 pubkey.
func peerSection(t *testing.T, pubB64, endpoint string, sec, nsec int64, tx, rx uint64) string {
	t.Helper()
	hexKey, err := b64tohex(pubB64)
	if err != nil {
		t.Fatalf("b64tohex(%q): %v", pubB64, err)
	}
	return fmt.Sprintf(
		"public_key=%s\npreshared_key=%s\nprotocol_version=1\nendpoint=%s\n"+
			"last_handshake_time_sec=%d\nlast_handshake_time_nsec=%d\n"+
			"tx_bytes=%d\nrx_bytes=%d\npersistent_keepalive_interval=25\nallowed_ip=10.80.0.1/32\n",
		hexKey, testPresharedHex, endpoint, sec, nsec, tx, rx,
	)
}

func TestParsePeers(t *testing.T) {
	hubKey := RandomKey().Public()
	otherKey := RandomKey().Public()

	t.Run("reads one peer", func(t *testing.T) {
		got, err := parsePeers(ipcFixture(peerSection(t, hubKey, "203.0.113.9:51821", 1758550000, 123000000, 38333, 2224)))
		if err != nil {
			t.Fatalf("parsePeers: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d peers, want 1", len(got))
		}
		p := got[0]
		if p.PublicKey != hubKey {
			t.Errorf("PublicKey = %q, want %q", p.PublicKey, hubKey)
		}
		if p.Endpoint != "203.0.113.9:51821" {
			t.Errorf("Endpoint = %q, want %q", p.Endpoint, "203.0.113.9:51821")
		}
		if want := time.Unix(1758550000, 123000000); !p.LastHandshake.Equal(want) {
			t.Errorf("LastHandshake = %v, want %v", p.LastHandshake, want)
		}
		if p.TxBytes != 38333 || p.RxBytes != 2224 {
			t.Errorf("tx/rx = %d/%d, want 38333/2224", p.TxBytes, p.RxBytes)
		}
	})

	t.Run("a peer that never handshook has a zero time", func(t *testing.T) {
		got, err := parsePeers(ipcFixture(peerSection(t, hubKey, "", 0, 0, 0, 0)))
		if err != nil {
			t.Fatalf("parsePeers: %v", err)
		}
		if !got[0].LastHandshake.IsZero() {
			t.Errorf("LastHandshake = %v, want the zero time", got[0].LastHandshake)
		}
	})

	t.Run("keeps two peers apart", func(t *testing.T) {
		got, err := parsePeers(ipcFixture(
			peerSection(t, hubKey, "203.0.113.9:51821", 1758550000, 0, 10, 20),
			peerSection(t, otherKey, "198.51.100.4:51821", 1758550500, 0, 30, 40),
		))
		if err != nil {
			t.Fatalf("parsePeers: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d peers, want 2", len(got))
		}
		if got[0].PublicKey != hubKey || got[1].PublicKey != otherKey {
			t.Errorf("keys = %q, %q", got[0].PublicKey, got[1].PublicKey)
		}
		if got[0].TxBytes != 10 || got[1].TxBytes != 30 {
			t.Errorf("tx = %d, %d, want 10, 30", got[0].TxBytes, got[1].TxBytes)
		}
	})

	t.Run("a device with no peers lists none", func(t *testing.T) {
		got, err := parsePeers(ipcFixture())
		if err != nil {
			t.Fatalf("parsePeers: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d peers, want 0", len(got))
		}
	})

	t.Run("never returns the device or peer secrets", func(t *testing.T) {
		got, err := parsePeers(ipcFixture(peerSection(t, hubKey, "203.0.113.9:51821", 1758550000, 0, 1, 2)))
		if err != nil {
			t.Fatalf("parsePeers: %v", err)
		}
		dump := fmt.Sprintf("%+v", got)
		for _, secret := range []string{testPrivateHex, testPresharedHex} {
			if strings.Contains(dump, secret) {
				t.Errorf("peer listing leaked a secret: %s", dump)
			}
		}
	})

	t.Run("reports a malformed number", func(t *testing.T) {
		bad := strings.Replace(
			ipcFixture(peerSection(t, hubKey, "", 1758550000, 0, 0, 0)),
			"tx_bytes=0", "tx_bytes=banana", 1,
		)
		if _, err := parsePeers(bad); err == nil {
			t.Fatal("parsePeers accepted a malformed tx_bytes")
		}
	})
}
