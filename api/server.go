/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package api

import (
	"net/http"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"errors"
)

func StartServer(port int, certificate, key []byte) error {
	block, _ := pem.Decode(certificate)
	if block == nil {
		block = &pem.Block{Bytes:certificate}
	}

	cert, e := tls.X509KeyPair(certificate, key)
	if e != nil {
		return e
	}

	if !verify(cert.Certificate[0]) {
		return errors.New("Server certificate is not valid for this CA")
	}
	server := http.Server{
		Addr:fmt.Sprintf(":%d", port),
		Handler:InitRouter(),
		TLSConfig:&tls.Config{
			Certificates:[]tls.Certificate{cert},
			ClientAuth:tls.RequestClientCert,
		},
	}
	return server.ListenAndServeTLS("", "")
}
