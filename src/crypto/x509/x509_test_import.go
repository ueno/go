// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// This file is run by the x509 tests to ensure that a program with minimal
// imports can sign certificates without errors resulting from missing hash
// functions.
package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

func main() {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	rsaPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("Failed to parse private key: " + err.Error())
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test",
			Organization: []string{"Σ Acme Co"},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),
		KeyUsage:  x509.KeyUsageCertSign,
	}

	if _, err = x509.CreateCertificate(rand.Reader, &template, &template, &rsaPriv.PublicKey, rsaPriv); err != nil {
		panic("failed to create certificate with basic imports: " + err.Error())
	}
}

// This key is generated with the following command:
//
//   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
//   openssl pkey -traditional -in key.pem > key-traditional.pem
//
var pemPrivateKey = testingKey(`
-----BEGIN RSA TESTING KEY-----
MIIEogIBAAKCAQEAp5qgUIj096pw8U+AjcJucLWenR3oe+tEthXiAuqcYgslW5UU
lMim34U/h7NbLvbG2KJ2chUsmLtuCFaoIe/YKW5DKm3SPytK/KCBsVa+MQ7zuF/1
ks5p7yBqFBl6QTekMzwskt/zyDIG9f3A+38akruHNBvUgYqwbWPx4ycclQ52GSev
/Cfx0I68TGT5SwN/eCJ/ghq3iGAf0mX1bkVaW1seKbL49aAA94KnDCRdl813+S2R
EPDf2tZwlT0JpZm5QtAqthonZjkjHocZNxhkKF3XWUntE/+l6R4A+CWZlC2vmUc1
hJTEraksy2JUIjxAaq//FnDpIEVG/N2ofmNpaQIDAQABAoIBAAYH7h9fwkLcNvqz
8+oF9k/ndSjtr9UvstYDhRG6S/zKLmK0g1xUOQ7/fjj9lvkiZ6bZd74krWlkizHR
HnU0KnjZLyEKeR+NSQI8q1YMi0T8JwB6MX3CIDU62x5UiV3p6OZwEqGJXf4U8MOu
ySAzo2rmxRd2reeobC9Pgp98I47oeqaSRwFVZRPfKk5RvfI7KRmL58BAB0XS56PA
PJ+3l0fB/oIV11iaBEKildxLDtrvlepQ2KPNf7Dpk0/CPRtS/jxyxIyML8tjR3F0
KuHplsRjTANyzW/aHddO1fnfnXsVo+0PzSPTHCbxKSu5XmChqsKoB1jM+/tJci4y
ST5hUXUCgYEAzfA5XEMkR/NNJMfR+FBbdfpQ1b0wqH3qtWZx/tBjKC2Y0XnDQ8ZR
SEWONLVZMRtTlJaHIPZ9i6anQRR5harrff0OpsKiJUGDout8ehE6eiN8ABWGNlCI
AiLCerVJZMDcSuDU7xsdHVIdSxYh88Z9g54vUQ4214BG/G0Qm1emV3UCgYEA0FjP
wq5cEGt9xDCg+oXk0bLm4Wn4FkabJH7M+oCosHHY9W1vgvv50bpNoAbaB5r1mlan
T6gEtkQPB2juMTnuIwRL+kvOmSKqZGlAsyrq8smTuBUv7brbybkYN3Rg51KV6u1J
vCdGpMYWHUNRkkQ88cr6iFPodYU+CzRR4ABif6UCgYBc0jDYb/7TW0tjD5mJJZcD
xw5WOE7NMuvuVT1+T6jRvDOL/yjOzH1oaMle4npQEvQKHgrMBa2ymyv5vmPDprU7
9Sp8aW+yASR281MIpelIkePbGdiDdKrI46fqrPlmqzLfoRT4rKzjwVYouNIW0VlT
UKIdE54OZegY8IOysL/t3QKBgDZnSnECiIW9G80UCaUBO3vKZGFuA1sFutMvzSSI
XgQc5lNH7TtdwqESLdzgjSQ5QXK4t92j+P8DDI2Zx8DQ6K76G0DTdLImDCpGFZ/z
UABvxIPn/GjuRyAIlhs852Tf+seqiHt6Igc6tmGTx4QTD3rvzrW0e1ncnhPc6Jg+
YXoFAoGARD9OPrd4J2N+nkSWif9VOuPHvOXEczwBDJbsAGrOW1kTbDStF0OIVOt0
Ukj+mnnL8ZNyVLgTrZDRfXvlA94EbPK5/rMAYwjMlXHP8R22ts3eDMNUdw0/Zl1g
QOhL8wXZcdwHKsONy55kZHo8pmneqi9EnqqLGguLwx5WIMzWvZ8=
-----END RSA TESTING KEY-----
`)

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
