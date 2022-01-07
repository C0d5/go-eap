package coreUtils

import "crypto/elliptic"

type SecurityParams struct {
	ServerKeyExchangePublicKey  []byte
	ClientKeyExchangePrivateKey []byte
	Curve                       elliptic.Curve
	ClientRandom                [32]byte
	ServerRandom                [32]byte
	ClientMAC                   []byte
	ServerMAC                   []byte
	ClientKey                   []byte
	ServerKey                   []byte
	ClientIV                    []byte
	ServerIV                    []byte
}
