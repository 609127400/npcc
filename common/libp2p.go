package common

import "crypto"

type P2PNodeConfig struct {
	Name       string
	Topic      string
	ProtocolID string
	Addr       string
	Bootstraps []string
	PrivKey    crypto.PrivateKey
}
