package main

import (
	"fmt"
	"log"

	"github.com/caddyserver/devportal"
)

const (
	addr   = ":2016"
	dbFile = "caddy.db"
)

func main() {
	fmt.Println("Developer portal serving at", addr)
	err := devportal.Serve(addr, dbFile)
	if err != nil {
		log.Fatal(err)
	}
}
