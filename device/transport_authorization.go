package device

import "github.com/sagernet/wireguard-go/conn"

func authorizeTransport(endpoint conn.Endpoint, peer NoisePublicKey) bool {
	if policy, ok := endpoint.(conn.PeerAuthorizingEndpoint); ok {
		return policy.AuthorizePeer([32]byte(peer))
	}
	return true
}
