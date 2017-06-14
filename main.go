package main

import (
	"./api"
	"os"
	"errors"
	"io/ioutil"
	"log"
	"strconv"
)

func main() {
	// args: port ca.crt server.crt server.key
	if len(os.Args) != 5 {
		usage();
	}
	port, e := strconv.Atoi(os.Args[1])
	if e != nil {
		die("port", e)
	}
	if port < 1 || port > 65535 {
		die("port", errors.New("Port must be between 1 and 65535"))
	}
	if e := api.LoadRootCA(os.Args[2]); e != nil {
		die("rootca", e)
	}
	if s_cert, e := ioutil.ReadFile(os.Args[3]); e != nil {
		die("servercert", e)
	} else {
		if s_key, e := ioutil.ReadFile(os.Args[4]); e != nil {
			die("serverkey", e)
		} else {
			die("start", api.StartServer(port, s_cert, s_key))
		}
	}
}

func die(stage string, reason error) {
	log.Fatal("Fatal error at stage", stage, "with error:", reason.Error())
}

func usage() {
	println("Usage:", os.Args[0], " <port> <rootca> <servercert> <serverkey>")
	println(" - port is a TCP port to listen to")
	println(" - rootca is a CA's PEM certificate to validate clients")
	println(" - servercert is a server's PEM  certificate ( signed by rootca )")
	println(" - serverkey is a server's RSA private  key")
	os.Exit(0)
}

