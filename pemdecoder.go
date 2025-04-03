package pemdecoder

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
)

// make struct 'type' that holds a shorthand 'type' (cert, crl, csr, key, p7?) and the JSON data so a front-end can format the data nicely

func DecodePEM(pemBlock string) (string, error) {
	//	First, attempt to decode the PEM and let Go handle the type
	var result interface{}

	block, _ := pem.Decode([]byte(pemBlock))

	if block == nil {
		//	If it fails, let's try some common types by adding headers and try the specidfic parsing
		block, _ = pem.Decode([]byte("\n-----BEGIN CERTIFICATE REQUEST-----\n" + pemBlock + "\n-----END CERTIFICATE REQUEST-----\n"))
		if block != nil {
			csr, err := x509.ParseCertificateRequest(block.Bytes)

			if err != nil {
				block, _ = pem.Decode([]byte("-----BEGIN CERTIFICATE-----\n" + pemBlock + "\n-----END CERTIFICATE-----\n"))
				if block != nil {
					cert, err := x509.ParseCertificate(block.Bytes)

					if err != nil {
						block, _ = pem.Decode([]byte("\n-----BEGIN PRIVATE KEY-----\n" + pemBlock + "\n-----END PRIVATE KEY-----\n"))

						if block != nil {
							key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
							if err != nil {
								err = errors.New("Error: Cannot decode.")
								return "", err
							}
							//	It was a private key
							result = key

							jsonBytes, err := json.Marshal(result)
							if err != nil {
								return "", err
							}

							return string(jsonBytes), nil
						}
					}
					//	It was a certificate
					result = cert

					jsonBytes, err := json.Marshal(result)
					if err != nil {
						return "", err
					}

					return string(jsonBytes), nil
				}
			}
			//	It was a CSR
			result = csr

			jsonBytes, err := json.Marshal(result)
			if err != nil {
				return "", err
			}

			return string(jsonBytes), nil
		}
	}

	//	PEM decodes first time, so switch and decode for the specific type
	switch block.Type {
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return "", err
		}
		result = csr
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		result = cert
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		result = key
	default:
		return "", errors.New("unknown PEM type")
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
