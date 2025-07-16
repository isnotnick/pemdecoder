package pemdecoder

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/grantae/certinfo"
)

// make struct 'type' that holds a shorthand 'type' (cert, crl, csr, key, p7?) and the JSON data so a front-end can format the data nicely
type DecodedPEM struct {
	PEMType       string `json:"pemtype"`
	GoDecode      string `json:"godecode"`
	OpenSSLDecode string `json:"openssldecode"`
}

func DecodePEM(pemBlock string) (string, error) {
	//	First, attempt to decode the PEM and let Go handle the type
	var result interface{}
	var finalDecode DecodedPEM

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
								err = errors.New("error: cannot decode")
								return "", err
							}
							//	It was a private key
							result = key

							jsonBytes, err := json.Marshal(result)
							if err != nil {
								return "", err
							}

							finalDecode.PEMType = "Private Key"
							finalDecode.GoDecode = string(jsonBytes)

							finalJsonBytes, err := json.Marshal(finalDecode)
							if err != nil {
								return "", err
							}

							return string(finalJsonBytes), nil
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
		finalDecode.PEMType = "CSR"
		csrPretty, err := certinfo.CertificateRequestText(csr)
		if err == nil {
			finalDecode.OpenSSLDecode = csrPretty
		}
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		result = cert
		finalDecode.PEMType = "Certificate"
		certPretty, err := certinfo.CertificateText(cert)
		if err == nil {
			finalDecode.OpenSSLDecode = certPretty
		}
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		result = key
		finalDecode.PEMType = "Private Key"
	default:
		return "", errors.New("unknown PEM type")
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}

	finalDecode.GoDecode = string(jsonBytes)

	finalJsonBytes, err := json.Marshal(finalDecode)
	if err != nil {
		return "", err
	}

	return string(finalJsonBytes), nil
}
