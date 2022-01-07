//TODO add licence
package cryptoHelpers

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	log "github.com/sirupsen/logrus"
	"github.com/C0d5/go-tls/coreUtils"
	"hash"
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")

const (
	masterSecretLength   = 48 // Length of a master secret in TLS 1.2.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
	keyLength            = 32 // Length of client and server key
	macLength            = 0
	ivLength             = 4
)

func prfAndHashForVersion() (func(result, secret, label, seed []byte), crypto.Hash) {
	return prf12(sha512.New384), crypto.SHA384
}

func prfForVersion() func(result, secret, label, seed []byte) {
	prf, _ := prfAndHashForVersion()
	return prf
}

// pHash implements the P_hash function, as defined in RFC 4346, Section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, Section 5.
func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See RFC 5246, Section 8.1.
func MasterFromPreMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	masterSecret := make([]byte, masterSecretLength)
	prfForVersion()(masterSecret, preMasterSecret, masterSecretLabel, seed)
	return masterSecret
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, Section 6.3.
func KeysFromMasterSecret(masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prfForVersion()(keyMaterial, masterSecret, keyExpansionLabel, seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

func GeneratePreMasterSecret(securityParams *coreUtils.SecurityParams) []byte {
	publicKeyX, publicKeyY := elliptic.Unmarshal(securityParams.Curve, securityParams.ServerKeyExchangePublicKey)
	if publicKeyX == nil {
		return nil
	}
	xShared, _ := securityParams.Curve.ScalarMult(publicKeyX, publicKeyY, securityParams.ClientKeyExchangePrivateKey)
	sharedKey := make([]byte, (securityParams.Curve.Params().BitSize+7)/8)
	return xShared.FillBytes(sharedKey)
}

// Returns the contents of the verify_data member of a client's Finished message.
func MakeVerifyData(securityParams *coreUtils.SecurityParams, data []byte) []byte {
	preMasterSecret := GeneratePreMasterSecret(securityParams)
	if preMasterSecret == nil {
		log.Warn("Could not generate PreMasterSecret")
		return nil
	}

	masterSecret := MasterFromPreMasterSecret(preMasterSecret, securityParams.ClientRandom[:], securityParams.ServerRandom[:])
	securityParams.ClientMAC, securityParams.ServerMAC, securityParams.ClientKey, securityParams.ServerKey, securityParams.ClientIV, securityParams.ServerIV =
		KeysFromMasterSecret(masterSecret, securityParams.ClientRandom[:], securityParams.ServerRandom[:], macLength, keyLength, ivLength)

	out := make([]byte, finishedVerifyLength)
	prfForVersion()(out, masterSecret, clientFinishedLabel, data)
	return out
}

// Returns the contents of the verify_data member of a client's Finished message.
func MakeVerifyDataUsingKeys(sharedKey,clientRandom,serverRandom,data []byte) []byte {
	masterSecret := MasterFromPreMasterSecret(sharedKey, clientRandom[:], serverRandom[:])
	// securityParams.ClientMAC, securityParams.ServerMAC, securityParams.ClientKey, securityParams.ServerKey, securityParams.ClientIV, securityParams.ServerIV =
	// 	KeysFromMasterSecret(masterSecret, securityParams.ClientRandom[:], securityParams.ServerRandom[:], macLength, keyLength, ivLength)

	out := make([]byte, finishedVerifyLength)
	prfForVersion()(out, masterSecret, clientFinishedLabel, data)
	return out
}
