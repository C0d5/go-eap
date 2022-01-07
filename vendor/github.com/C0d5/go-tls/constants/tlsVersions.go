package constants

type TlsVersionConverter struct {
	TlsVersions map[string][2]byte
}

func MakeTlsVersionConverter() TlsVersionConverter {
	tlsVersionConverter := TlsVersionConverter{}
	tlsVersionConverter.TlsVersions = map[string][2]byte {
		"TLS 1.0": {0x03, 0x01},
		"TLS 1.1": {0x03, 0x02},
		"TLS 1.2": {0x03, 0x03},
		"TLS 1.3": {0x03, 0x04},
	}

	return tlsVersionConverter
}

func (converter TlsVersionConverter)GetByteCodeForVersion(version string) [2]byte {
	return converter.TlsVersions[version]
}

func (converter TlsVersionConverter)GetVersionForByteCode(version [2]byte) string {
	for k, v := range converter.TlsVersions {
		if v == version {
			return k
		}
	}

	return ""
}


var GTlsVersions = MakeTlsVersionConverter()
