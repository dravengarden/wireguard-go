package device_test

import (
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

type authorizingEndpoint struct {
	conn.Endpoint
	authorize func([32]byte) bool
}

func (e *authorizingEndpoint) AuthorizePeer(peer [32]byte) bool { return e.authorize(peer) }

type authorizingBind struct {
	conn.Bind
	authorize func([32]byte) bool
}

func (b *authorizingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	functions, port, err := b.Bind.Open(port)
	for i, receive := range functions {
		functions[i] = func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			n, err := receive(packets, sizes, endpoints)
			for j := 0; j < n; j++ {
				endpoints[j] = &authorizingEndpoint{Endpoint: endpoints[j], authorize: b.authorize}
			}
			return n, err
		}
	}
	return functions, port, err
}
func (b *authorizingBind) Send(packets [][]byte, endpoint conn.Endpoint, offset int) error {
	if e, ok := endpoint.(*authorizingEndpoint); ok {
		endpoint = e.Endpoint
	}
	return b.Bind.Send(packets, endpoint, offset)
}

// Real Noise handshakes and encrypted packets prove authorization happens
// against the authenticated key, before handshake acceptance and TUN delivery.
func TestAuthenticatedTransportAuthorization(t *testing.T) {
	serverPrivate, serverPublic := generateTestKeyPair(t)
	clientPrivate, clientPublic := generateTestKeyPair(t)
	decoded, err := hex.DecodeString(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	var expected [32]byte
	copy(expected[:], decoded)
	var allow atomic.Bool
	observed := make(chan [32]byte, 32)
	bind := &authorizingBind{Bind: conn.NewStdNetBind(nil), authorize: func(peer [32]byte) bool {
		select {
		case observed <- peer:
		default:
		}
		return allow.Load() && peer == expected
	}}
	server, output := startTestDevice(t, "authorized-server", serverPrivate, clientPublic, "10.0.0.2/32", bind)
	defer server.Close()
	client, input := startTestDevice(t, "authorized-client", clientPrivate, serverPublic, "10.0.0.1/32")
	defer client.Close()
	if err := client.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d", serverPublic, devicePort(t, server))); err != nil {
		t.Fatal(err)
	}
	input.inbound <- buildTestPacket()
	select {
	case peer := <-observed:
		if peer != expected {
			t.Fatal("authorization did not receive authenticated identity")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handshake authorization was not consulted")
	}
	select {
	case <-output.outbound:
		t.Fatal("denied handshake delivered data")
	case <-time.After(200 * time.Millisecond):
	}
	allow.Store(true)
	input.inbound <- buildTestPacket()
	select {
	case <-output.outbound:
	case <-time.After(15 * time.Second):
		t.Fatal("approved handshake did not deliver data")
	}
	// Both requests queued while the handshake was denied are staged and
	// delivered once it succeeds. Drain that accepted traffic before revocation.
	select {
	case <-output.outbound:
	case <-time.After(3 * time.Second):
		t.Fatal("second staged request was not delivered")
	}
	for len(observed) > 0 {
		<-observed
	}
	allow.Store(false)
	input.inbound <- buildTestPacket()
	select {
	case <-observed:
	case <-time.After(3 * time.Second):
		t.Fatal("established data authorization was not consulted")
	}
	select {
	case <-output.outbound:
		t.Fatal("revoked data reached TUN")
	case <-time.After(200 * time.Millisecond):
	}
	allow.Store(true)
	input.inbound <- buildTestPacket()
	select {
	case <-output.outbound:
	case <-time.After(3 * time.Second):
		t.Fatal("authorized data did not recover on the existing session")
	}
}
