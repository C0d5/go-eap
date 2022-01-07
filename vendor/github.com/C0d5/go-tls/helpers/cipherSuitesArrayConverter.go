package helpers

import (
	"github.com/C0d5/go-tls/constants"
)

func ConvertByteArrayToCipherSuites(byteArray []byte) []string {
	var cipherSuites []string
	for i := 0; i < len(byteArray); i += 2 {
		suiteArray := [2]byte{byteArray[i], byteArray[i+1]}
		cipherSuites = append(cipherSuites, constants.GCipherSuites.GetSuiteForByteCode(suiteArray))
	}
	return cipherSuites
}
