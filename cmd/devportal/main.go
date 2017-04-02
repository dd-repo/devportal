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
	flag.StringVar(&devportal.Log, "log", devportal.Log,
		"Log file (or stdout/stderr; empty for none)")
	flag.IntVar(&devportal.MaxCachedBuilds, "cachesize", devportal.MaxCachedBuilds,
		"The maximum number of builds to cache (minimum 1)")
	flag.StringVar(&devportal.BuildCacheDir, "cachedir", devportal.BuildCacheDir,
		"The directory in which to store cached builds")
	flag.StringVar(&devportal.BuildWorkerUpstream, "buildworker", devportal.BuildWorkerUpstream,
		"The base URL to the upstream build worker")
	flag.StringVar(&devportal.SiteRoot, "siteroot", devportal.SiteRoot,
		"Path to the root of the Caddy site")

	devportal.BuildWorkerClientID = os.Getenv("BUILDWORKER_CLIENT_ID")
	devportal.BuildWorkerClientKey = os.Getenv("BUILDWORKER_CLIENT_KEY")
}

var (
	addr   = ":2016"
	dbFile = "caddy.db"
)

func main() {
	flag.Parse()

	if devportal.SiteRoot == "" {
		log.Fatal("Where do I find the site? Run with -siteroot and specify the path to the root of the site.")
	}
	if devportal.BuildWorkerClientID == "" && devportal.BuildWorkerClientKey == "" {
		fmt.Println("WARNING: No auth for upstream build workers. Set BUILDWORKER_CLIENT_ID and BUILDWORKER_CLIENT_KEY.")
	}
	if os.Getenv("SENDGRID_API_KEY") == "" {
		fmt.Println("WARNING: Emails will not be sent. Set SENDGRID_API_KEY.")
	}

	fmt.Println("Developer portal serving at", addr)
	err := devportal.Serve(addr, dbFile)
	if err != nil {
		log.Fatal(err)
	}
}
