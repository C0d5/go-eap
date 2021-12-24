package eap

type dictionary struct {
    AVPMeta avpMeta `xml:"eap"`
    EAPSUB   eapSType   `xml:"eapsub"`
}

type avpMeta struct {
	Code string `xml:"code,attr"`
	Name string `xml:"name,attr"`
	Reserved string `xml:"reserved,attr"`
}

type eapSType struct {
	Subtype string `xml:"subtype,attr"`
	Name string `xml:"name,attr"`
}