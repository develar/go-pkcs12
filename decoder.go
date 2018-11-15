package pkcs12

import (
	"crypto/x509"
)

func DecodeAllCerts(pfxData []byte, password string) ([]*x509.Certificate, error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)
	if err != nil {
		return nil, err
	}

	var result []*x509.Certificate
	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, err
			}
			result = append(result, certs...)
		}
	}
	return result, nil
}
