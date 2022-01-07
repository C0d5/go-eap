package constants

import "crypto/elliptic"

type CurveInfo struct {
	Code  [2]byte
	Curve elliptic.Curve
}

type CurveConverter struct {
	Curves map[string]CurveInfo
}

func MakeCurveConverter() CurveConverter {
	CurveConverter := CurveConverter{}
	CurveConverter.Curves = map[string]CurveInfo {
		"SECP256R1": {
			Code:  [2]byte {0x00, 0x17},
			Curve: elliptic.P256(),
		},
		"SECP384R1": {
			Code:  [2]byte {0x00, 0x18},
			Curve: elliptic.P384(),
		},
		"X25519" : {
			Code:  [2]byte {0x00, 0x1d},
			Curve: nil, //unsupported by elliptic package
		},
	}

	return CurveConverter
}

func (converter CurveConverter) GetByteCodeForCurve(curve string) CurveInfo {
	return converter.Curves[curve]
}

func (converter CurveConverter) GetCurveForByteCode(curve [2]byte) string {
	for k, v := range converter.Curves {
		if v.Code == curve {
			return k
		}
	}

	return ""
}

func (converter CurveConverter) GetCurveInfoForByteCode(curve [2]byte) *CurveInfo {
	for _, v := range converter.Curves {
		if v.Code == curve {
			return &v
		}
	}

	return nil
}

var GCurves = MakeCurveConverter()
