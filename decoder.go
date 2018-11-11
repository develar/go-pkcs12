package pkcs12

import (
	"crypto/x509"
	"errors"
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
			if len(certs) != 1 {
				err = errors.New("pkcs12: expected exactly one certificate in the certBag")
				return nil, err
			}
			result = append(result, certs[0])
		}
	}

	return result, nil
}
