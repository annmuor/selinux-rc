/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package api

import (
	"crypto/x509"
	"encoding/pem"
	"sort"
	"log"
	"errors"
	"net/http"
	"io/ioutil"
)

var root string = `-----BEGIN CERTIFICATE-----
MIIFADCCAuigAwIBAgIJAOadPkS4424aMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNV
BAMMCnNlbGludXguY2EwHhcNMTcwNjE0MTQxMDAxWhcNNDQxMDMwMTQxMDAxWjAV
MRMwEQYDVQQDDApzZWxpbnV4LmNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAzcDsTXQnzZT2Q89UxYeaetuXyXKeeZAJP7QJAZ3oyNtPvJK2/U9TqB2Q
mUtybgnpRWLqs/zOAtpdxBm7C+PO2y/jJmuT9vlm9N84pCrb9vcc9Ojc10HLYyp5
cNadp3ePJUfVETpnCiSnWab6VKBHjNVepCdRnBDItCzHQlcpBnhspzEFT4sQO/kA
Wis65EvG7RnmTPlydHau2NlNg/MY/MAk5yyNzNRf2OAiIa1u6EiBUEljsjEyjtTN
FEQkE4SIyEsuTd3t7ST6Ujwownocb0JhS8HF6RVr/SO7hoXGwkFlPI1VpfknVnW8
E2FmZQxUFYlG0GPI472jYb86w6ymlFS/sffdPGBtOvfjFcoEDkOU5nHhavLql3rJ
Y6MW0Fgnv4GRv5NFiVt0Rt7QJMeeU98Nc+7JwZPwQ5HSfGtWL+oXpomi/bOFQ6T2
tp1X1iqC4lcmML92zqu5++Oo8uTrcCsGK6eIJyVXBLHUEZSc4ZDGbi+WsnRZDo/w
u1ID+A3LTeli3t6p7e8s5rDvgFK3p1PhTxdnTIL3QH0xyEcukZA1zZeMzCRNaxOv
QjQvjmzCxSfJWQ/qy36B0EiHWrTtdvbsq7Jnm1JqUnByji6gkk6OMykUdXTCh65W
Y//A2UH9+HCeundB91MPS4qTK4qZpij3vA/ivoHqfHwZuOm2a1ECAwEAAaNTMFEw
HQYDVR0OBBYEFGle5ymaku/a0WCcTBYx9Sfe5DhxMB8GA1UdIwQYMBaAFGle5yma
ku/a0WCcTBYx9Sfe5DhxMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD
ggIBAC8+rJ4L0LLvev8hHM7H0rcDD9HcaIVJCvkVVUhVlkXed/fWd19KXG0QjrNv
VOflksJVHzbWRJflSTqMnSHYhVUaH0RPhtD5LLVQlICzHLKSys0cQr//cPqVKCkK
T17CquOtTymwczH/oWff0m/io5w1s29myQpwGYVzO2X9CavxWeSSwcX5BAydAait
LLOOO//A+alDiCeUUXMiSX543iTPdgy6H59ytRpp0FT3Vnp43OM4FPVOs8vC3JiX
5v0KyDVqSx7UrS3QkErf3UR9GbsVJQdIv2SlPijmJYqlFopk8kdfBI9be84IkF2r
MfwGdB+3WhASAWF0yVvB24laXdLjKqXRxqOe9b8bMgZ1T7a/GtCaltpLL5vysggF
HdithD/ax4gMppbkPhIMjC2ZLPKESS6lbqPorhx5gLQyCKixqWPDEC/+5846uqxZ
4az4XTRoNDyUN2ErXWqcPlXFzVdh0fK2KZDOAiOdRJxhr26x1wZjq5DZolbQNIZT
sBOQY7MUVE+/lv+oGdDqarF2ncC40fTcD2emMA7JwmLLVTdQc3iX/hcOtpTLEEUm
I+YLidN2sQJ2pNar+ixG8Kfg1MeGHDz8mCEcJ6TGR1+kZfVEFdPDz7a8TEjazc7S
Elt+56uMERW8BAvY8BFI3qlAOvoNRjzl14LjpQQ6xQD4ArVo
-----END CERTIFICATE-----`

var rootca int = 720575940379279360 // as example

type int64slice []int64

func (a int64slice) Len() int {
	return len(a)
}
func (a int64slice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a int64slice) Less(i, j int) bool {
	return a[i] < a[j]
}

var roots *x509.CertPool
var veropts *x509.VerifyOptions

func LoadRootCA(filename string) error {
	_root, e := ioutil.ReadFile(filename)
	if e == nil {
		root = string(_root)
		rootca = checksum()
		return security_init()
	} else {
		return e
	}
}

func checksum() int {

	bs := []byte(root) // to root
	i := []int64{}
	step := 0
	var newint int64 = 0
	for _, b := range bs {
		switch(step) {
		case 7:
			newint |= int64(b) << 56
			step = 0
			i = append(i, newint)
			newint = 0
			break
		default:
			step += 1
			newint |= (int64(b) << uint(8 * step))
			newint = 0

		}
	}
	sort.Sort(int64slice(i))
	return int(i[0])
}

func security_init() error {
	if checksum() != rootca {
		return errors.New("RootCA is invalid")
	}
	if roots != nil {
		if veropts != nil {
			return nil
		} else {
			veropts = &x509.VerifyOptions{
				Roots:roots,
			}
		}
	} else {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(root)) {
			return errors.New("RootCA is invalid")
		}
		veropts = &x509.VerifyOptions{
			Roots:roots,
		}
	}
	return nil
}

func verify(data []byte) bool {
	block, _ := pem.Decode(data)
	if block == nil {
		block = &pem.Block{Bytes:data} // try again
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return verifyCert(cert)
}

func verifyCert(cert *x509.Certificate) bool {
	if e := security_init(); e != nil {
		log.Fatal(e.Error())
		return false
	}
	if _, e := cert.Verify(*veropts); e == nil {
		return true
	}
	return false
}

func is_verified(r *http.Request) bool {
	verified := false
	for _, c := range r.TLS.PeerCertificates {
		if verifyCert(c) {
			verified = true
		}
	}
	return verified
}