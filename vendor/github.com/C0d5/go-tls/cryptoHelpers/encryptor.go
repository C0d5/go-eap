package cryptoHelpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/C0d5/go-tls/coreUtils"
	"github.com/C0d5/go-tls/helpers"
	"io"
)

const (
	AESGCM_NonceSize = 8
	AuthenticationTagSize = 16
)

// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 uses an AEAD cipher for authentication
// AEAD ciphers take as input a single key, a nonce, a plaintext, and
// "additional data" to be included in the authentication check.
// The key is either the client_write_key or the server_write_key. No MAC key is used.
func Encrypt(clientKey, clientIV, plaintext []byte, additionalData *coreUtils.AdditionalData) ([]byte, error) {
	aesEncryptor, err := aes.NewCipher(clientKey)
	if err != nil {
		log.Error("Could not create the cipher: ", err.Error())
		return nil, err
	}
	gcmAuthenticator, err := cipher.NewGCM(aesEncryptor)
	if err != nil {
		log.Error("Failed to get cipher: ", err.Error())
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given clientKey because of the risk of a repeat.
	nonce := make([]byte, AESGCM_NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	nonceIV := append(clientIV, nonce...)

	additionalDataPayload := make([]byte, 7)
	additionalDataPayload = append(additionalDataPayload, additionalData.SeqNumber)
	additionalDataPayload = append(additionalDataPayload, additionalData.RecordType)
	additionalDataPayload = append(additionalDataPayload, additionalData.TlsVersion[:]...)

	contentBytesLength := helpers.ConvertIntToByteArray(uint16(len(plaintext)))
	additionalDataPayload = append(additionalDataPayload, contentBytesLength[:]...)

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data (aad) and returns ciphertext together with authentication tag.
	ciphertext := gcmAuthenticator.Seal(nil, nonceIV, plaintext, additionalDataPayload)
	if ciphertext == nil {
		log.Error("AEAD.Seal: Failed to encrypt message")
		return nil, errors.New("math: Failed to encrypt message")
	}

	return append(nonce, ciphertext...), nil
}

func Decrypt(serverKey, serverIV, ciphertext []byte, additionalData *coreUtils.AdditionalData) ([]byte, error) {
	aesEncryptor, err := aes.NewCipher(serverKey)
	if err != nil {
		log.Error("Could not create the cipher: ", err.Error())
		return nil, err
	}
	gcmAuthenticator, err := cipher.NewGCM(aesEncryptor)
	if err != nil {
		log.Error("Failed to encrypt message: ", err.Error())
		return nil, err
	}

	nonce, rest := ciphertext[:AESGCM_NonceSize], ciphertext[AESGCM_NonceSize:]
	nonceIV := append(serverIV, nonce...)

	// extend seqNumber to 8 bytes
	additionalDataPayload := make([]byte, 7)
	additionalDataPayload = append(additionalDataPayload, additionalData.SeqNumber)
	additionalDataPayload = append(additionalDataPayload, additionalData.RecordType)
	additionalDataPayload = append(additionalDataPayload, additionalData.TlsVersion[:]...)

	contentBytesLength := helpers.ConvertIntToByteArray(uint16(len(rest) - AuthenticationTagSize))
	additionalDataPayload = append(additionalDataPayload, contentBytesLength[:]...)

	plaintext, err := gcmAuthenticator.Open(nil, nonceIV, rest, additionalDataPayload)
	if err != nil {
		log.Error("Failed to decrypt message: ", err.Error())
		return nil, err
	}

	return plaintext, nil
}
