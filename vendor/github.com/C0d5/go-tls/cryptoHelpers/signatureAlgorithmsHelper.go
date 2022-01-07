package cryptoHelpers

import (
	"hash"
)

// Apply hashing function based on given name to hash message
func HashByteArray(hashAlgorithm func() hash.Hash, byteArray []byte) []byte {
	hashFunc := hashAlgorithm()
	hashFunc.Write(byteArray)
	hashedOutput := hashFunc.Sum(nil)
	return hashedOutput
}
