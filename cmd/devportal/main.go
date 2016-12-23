package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/caddyserver/devportal"
)

func init() {
	flag.StringVar(&addr, "addr", addr, "The address (host:port) to listen on")
	flag.StringVar(&dbFile, "db", dbFile, "Path to the database file")
	flag.IntVar(&devportal.MaxCachedBuilds, "cachesize", devportal.MaxCachedBuilds,
		"The maximum number of builds to cache (minimum 1)")
	flag.StringVar(&devportal.BuildCacheDir, "cachedir", devportal.BuildCacheDir,
		"The directory in which to store cached builds")
	flag.StringVar(&devportal.BuildWorkerUpstream, "buildworker", devportal.BuildWorkerUpstream,
		"The base URL to the upstream build worker")

	devportal.BuildWorkerClientID = os.Getenv("BUILDWORKER_CLIENT_ID")
	devportal.BuildWorkerClientKey = os.Getenv("BUILDWORKER_CLIENT_KEY")
}

var (
	addr   = ":2016"
	dbFile = "caddy.db"
)

func main() {
	flag.Parse()

	fmt.Println("Developer portal serving at", addr)
	err := devportal.Serve(addr, dbFile)
	if err != nil {
		log.Fatal(err)
	}
}
