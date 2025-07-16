package pemdecoder

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestCSRDecode(t *testing.T) {
	csrTest := `-----BEGIN CERTIFICATE REQUEST-----
MIIBoTCCAScCAQAwcDELMAkGA1UEBhMCR0IxFjAUBgNVBAgTDVN0YXRlT2ZEZW5p
YWwxETAPBgNVBAcTCExvY2F0aW9uMRAwDgYDVQQKEwdPcmdOYW1lMRAwDgYDVQQL
EwdPVW5ubm5uMRIwEAYDVQQDEwl0aGlzaXNhQ04wdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAARNToXdMpUNJ5ab+RSUiekt/vUD/bBdDaWZAdeljrhHxU6E0TJ/Re13Gh3i
WMAkpaYKA0H+xwRkoUNV5vpc1TyFNcfz2BHRg0Mi52JmDIl87tvQfErx8EEGN9pE
ZHyZ/w6gODA2BgkqhkiG9w0BCQ4xKTAnMCUGA1UdEQQeMByCCHBhc3MuY29tggZu
by5jb22CCHRlc3QuY29tMAoGCCqGSM49BAMCA2gAMGUCMG85qj2BsdCcTV/fb5wJ
EAJJFLZ0O4F5553HYUDHNht/aSDfZSQSXT3uA3g/GGsHkwIxALLZH6dT6DoiO+g2
Zz0r7Yhcw0Du7fC+rovAYZvHlfwFQ/ijKfQzdipQAb8SMbS8sQ==
-----END CERTIFICATE REQUEST-----`
	csrDecode, err := DecodePEM(csrTest)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(csrDecode)
	//PrettyPrint(csrDecode)
}

func TestECKeyDecode(t *testing.T) {
	keyTest := `-----BEGIN EC PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDRzgHBw1qB6RoVD1vN
SwKE/H98S3e/LgnafU4CtCYSiW6YlMajDserWoMpb2PCbRuhZANiAARNToXdMpUN
J5ab+RSUiekt/vUD/bBdDaWZAdeljrhHxU6E0TJ/Re13Gh3iWMAkpaYKA0H+xwRk
oUNV5vpc1TyFNcfz2BHRg0Mi52JmDIl87tvQfErx8EEGN9pEZHyZ/w4=
-----END EC PRIVATE KEY-----
`
	keyDecode, err := DecodePEM(keyTest)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(keyDecode)
	//PrettyPrint(csrDecode)
}

func TestRSAKeyDecode(t *testing.T) {
	keyTest := `-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2LOHoAlEU+EY3
fenk1H8QiUBxdZ75/ghLU/LV04pkZSLzH/hKgahFkZ5wWiS48OuQOGw59qIyFy28
eO6aMbP/ghtNO56ISRZEX1yZg7NXUQ8OtO0ZXvHe6pWLIFxSo3S2OZwHB2pD6Dqf
yFUvEgYQbFIOUpGhFO/DRtTJdDzsjePHHEupNUQBnUPNatHBye6+LbHMRZBpAFyZ
exsYkNLyHfz+/dDbfIt+Dj8TOpAJxam6f26Q522+tWpUZQQ81TcvLgkeJr5gU7Gy
PmNVD34zNaGHgdJdxNP+/fRw5Ou+clBsgEIdwgUl0WbgBpKAXnmGJut2LOO8h3Fn
jtn9XunpAgMBAAECggEAL8zfCa1x8PqkEfNr56sKHCCnVB30tMu/CWThltGGwoj2
/qwozgPvTzHCTOCaOhyc8p6bZyobrOEAEy/4C2V3QVe2KjG2izQCL7aF6ZHxALw4
Ize97qZG+KK80mCPWO+itB2xnvaHH4JTv5ElKNCl3rFNZoyrwYRo1OhE9QcW5Up0
YD3drNoqAFXE4Wo4iUZL5DT0VOvVO+/tY6b78laUsxsBiM30Tpgfjnuixkc+nHqD
c6jqe9IY60JMpv5RmgdO5+o9P39S7dTXHt6JeZ95GrZ0XlyMSbh3evmX25bakHTI
0gbvnWD+wE9EBw3Q4QyGGQlNxGBfDodXkIUP+J4twQKBgQDZ+khMXOC/8H/hgmVF
7Scc1Zm6df4N5VoD+0N/Y/CsBZIptQABybOuZEIj3J8ct2b4m4EFX0gMbeRv/jDC
MdlVNLGp6IGfH/L+g3U160rD/QnJoJl8EMR4OsZrR2kgIPa3naaq/qiBs4gxMxw5
sjr6cE53/9VnVZUH8tzZlQEOJQKBgQDV89vUQ3Wzm+0hoqGYKipV5AopkXfkDvn+
DPjozS584yRR87aDMjt2hODAQP+J5RTK/g7Qf/rlQWejMpv7prC345ohA8tQ9RyP
3+sssjmj96bTPrpx9QlkWYyWuLerWZtgfhsCiu7vJpHLZ+4384OuKkeWNrY8hdEn
D6G8y3u3dQKBgQCs50QMFqxMdCfsKHPOuOQKkkCD0G56dVAm0ltjJFJXEYA0Rxe/
U1CM54gzTCCGNdCfKTJ5oW/UNCM81sO0drgvR0IaRYz0PPKSApKp937x4biu0A6P
g/lkaTLVC+sOijdJxOrcvm3JnDBO3nzoI0F3QDhuJWgQtKknifS3PuN8ZQKBgE5f
mQxldc1IdhIXKAi8kWuLMGnPvtJM5ii5CckFuFzJO/nFQ/tFQGEHBemHJdSWlQpT
DIw2BWtLjTJMDLWfdya1ejVT1Xuffkn55YUm+FRnGLZTSSsLbthSsVxY5/cdyPwM
1coVqLb0Mv4G4U2fp4H6POT6v8Dl6Brd8Apfo78tAoGBALCUwcbKLoou4/lYjYBc
n/S7ErioF+3f3mm+A354wwmiWPxh36HoGGQ13VhIfMMBWmhBF1fYE1BWwmxp80Fs
1HW+URtvWuDeEORBULutxFsPLpdLRpKIb65GFYgNal6T0lFJ8n71UWe6kKi5HAwA
UYprdi9VMKUEETKpscdvLQDL
-----END RSA PRIVATE KEY-----
`
	keyDecode, err := DecodePEM(keyTest)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(keyDecode)
	//PrettyPrint(csrDecode)
}

func PrettyPrint(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	println(string(b))
}
