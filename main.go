/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package main

import (
	"os"
	"errors"
	"io/ioutil"
	"log"
	"./api"
	"./plugins"
	"flag"
)

func main() {
	config := flag.String("conf", "plugins.json", "json config for plugins data")
	port := flag.Int("port", 8443, "port to listen on")
	ca := flag.String("ca", "example/pki/ca.crt", "CA PEM certificate file")
	scert := flag.String("cert", "example/pki/server.crt", "Server PEM certificate file")
	skey := flag.String("key", "example/pki/server.key", "Server RSA key file")
	flag.Parse()

	if *port < 1 || *port > 65535 {
		die("port", errors.New("Port must be between 1 and 65535"))
	}
	if e := api.LoadRootCA(*ca); e != nil {
		die("rootca", e)
	}
	if s_cert, e := ioutil.ReadFile(*scert); e != nil {
		die("servercert", e)
	} else {
		if s_key, e := ioutil.ReadFile(*skey); e != nil {
			die("serverkey", e)
		} else {
			if *config != "" {
				plugins.LoadConfig(*config)
			}
			die("start", api.StartServer(*port, s_cert, s_key))
		}
	}
}

func die(stage string, reason error) {
	log.Fatal("Fatal error at stage", stage, "with error:", reason.Error())
}

func usage() {
	println("Usage:", os.Args[0], "[-c config] <port> <rootca> <servercert> <serverkey>")
	println(" - config - json config for plugins data")
	println(" - port is a TCP port to listen to")
	println(" - rootca is a CA's PEM certificate to validate clients")
	println(" - servercert is a server's PEM  certificate ( signed by rootca )")
	println(" - serverkey is a server's RSA private  key")
	os.Exit(0)
}
