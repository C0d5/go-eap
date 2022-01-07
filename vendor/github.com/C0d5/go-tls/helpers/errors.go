package helpers

type ParsingError struct {
	IsServerHelloParsingError             bool
	IsServerKeyExchangeMissingError       bool
	IsServerHelloMissingError             bool
	IsServerCertificateMissingError       bool
	IsServerHelloDoneMissingError         bool
	IsServerChangeCipherSpecMissingError  bool
	IsServerHandshakeFinishedMissingError bool
	IsApplicationDataMissingError         bool
}

func (pe *ParsingError) Error() string {
	if pe.IsServerHelloParsingError {
		return "ServerHello parsing error encountered!"
	}
	if pe.IsServerHelloMissingError {
		return "ServerHello missing!"
	}
	if pe.IsServerCertificateMissingError {
		return "ServerCertificate missing!"
	}
	if pe.IsServerKeyExchangeMissingError {
		return "ServerKeyExchange missing!"
	}
	if pe.IsServerHelloDoneMissingError {
		return "ServerHelloDone missing!"
	}
	if pe.IsServerChangeCipherSpecMissingError {
		return "ServerChangeCipherSpec missing!"
	}
	if pe.IsServerHandshakeFinishedMissingError {
		return "ServerHandshakeFinished missing!"
	}
	if pe.IsApplicationDataMissingError {
		return "ApplicationData missing!"
	}
	return "Undefined error"
}

func ServerHelloParsingError() error {
	return &ParsingError{IsServerHelloParsingError: true}
}

func ServerHelloMissingError() error {
	return &ParsingError{IsServerHelloMissingError: true}
}

func ServerCertificateMissingError() error {
	return &ParsingError{IsServerCertificateMissingError: true}
}

func ServerKeyExchangeMissingError() error {
	return &ParsingError{IsServerKeyExchangeMissingError: true}
}

func ServerHelloDoneMissingError() error {
	return &ParsingError{IsServerHelloDoneMissingError: true}
}

func ServerChangeCipherSpecMissingError() error {
	return &ParsingError{IsServerChangeCipherSpecMissingError: true}
}

func ServerHandshakeFinishedMissingError() error {
	return &ParsingError{IsServerHandshakeFinishedMissingError: true}
}

func ApplicationDataMissingError() error {
	return &ParsingError{IsApplicationDataMissingError: true}
}
