package devportal

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/buildworker"
	"github.com/gorilla/mux"
)

// The list of platforms on which each plugin must build
// successfully, or the deploy will be rejected.
var requiredPlatforms = []buildworker.Platform{
	{OS: "darwin", Arch: "amd64"},
	{OS: "linux", Arch: "386"},
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
	{OS: "linux", Arch: "arm", ARM: "6"},
	{OS: "linux", Arch: "arm", ARM: "7"},
	{OS: "freebsd", Arch: "386"},
	{OS: "freebsd", Arch: "amd64"},
	{OS: "openbsd", Arch: "386"},
	{OS: "openbsd", Arch: "amd64"},
	{OS: "windows", Arch: "386"},
	{OS: "windows", Arch: "amd64"},
}

func newBuildWorkerRequest(method, endpoint string, jsonBody io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, BuildWorkerUpstream+endpoint, jsonBody)
	if err != nil {
		return nil, err
	}
	if jsonBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(BuildWorkerClientID, BuildWorkerClientKey)
	return req, nil
}

func deployPlugin(pluginID, pkg, version string, account AccountInfo) error {
	now := time.Now().UTC()

	// get current released version of Caddy to check plugin against
	caddyRel, err := loadLatestCaddyRelease()
	if err != nil {
		return err
	}

	// make request for upstream build worker
	j, err := json.Marshal(buildworker.DeployRequest{
		CaddyVersion:      caddyRel.Version,
		PluginPackage:     pkg,
		PluginVersion:     version,
		RequiredPlatforms: requiredPlatforms,
	})
	if err != nil {
		return err
	}

	// prepare our request
	req, err := newBuildWorkerRequest("POST", "/deploy-plugin", bytes.NewReader(j))
	if err != nil {
		return err
	}

	go func() {
		// TODO: On any failure here, notify account...

		// send blocking request upstream to build worker
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("plugin deploy failed, network error: %v", err)
			return
		}
		defer resp.Body.Close()

		// handle any error with the build
		if resp.StatusCode >= 400 {
			bodyText, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("failed to read response body: %v", err)
			}
			log.Printf("plugin deploy failed: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(bodyText))
			return
		}

		// if successful, save the release to the DB
		err = savePluginRelease(pluginID, PluginRelease{
			Timestamp:    now,
			Version:      version,
			CaddyVersion: caddyRel.Version,
		})
		if err != nil {
			log.Printf("plugin deploy succeeded but failed to save: %v", err)
			return
		}

		// evict cached builds with this plugin; not really necessary except
		// if the plugin is deployed at a branch, since the cache key won't
		// be different, since branch names don't change while the ref does.
		// to avoid serving stale content, we just purge these cached builds.
		err = evictBuildsFromCache(pluginID)
		if err != nil {
			log.Printf("evicting affected builds from cache: %v", err)
			return
		}

		// TODO: Notify account of success
	}()

	return nil
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	produceDownload("archive", w, r)
}

func signatureHandler(w http.ResponseWriter, r *http.Request) {
	produceDownload("signature", w, r)
}

func produceDownload(ofWhat string, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Expose-Headers", "Location")

	now := time.Now().UTC()

	vars := mux.Vars(r)
	os := vars["os"]
	arch := vars["arch"]
	var arm string
	if strings.HasPrefix(arch, "arm") {
		arm = arch[3:]
		arch = arch[:3]
	}

	// check that the platform is supported
	supportedPlatformsMu.RLock()
	numPlats := len(supportedPlatforms)
	supportedPlatformsMu.RUnlock()
	if numPlats == 0 {
		// make sure we get the list first
		err := updateSupportedPlatforms()
		if err != nil {
			log.Printf("error checking supported platforms: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	supportedPlatformsMu.RLock()
	var supported bool
	for _, plat := range supportedPlatforms {
		if os == plat.OS && arch == plat.Arch && arm == plat.ARM {
			supported = true
			break
		}
	}
	supportedPlatformsMu.RUnlock()
	if !supported {
		log.Printf("platform not supported: GOOS=%s GOARCH=%s GOARM=%s", os, arch, arm)
		http.Error(w, "platform not supported", http.StatusBadRequest)
		return
	}

	pluginsQuery := strings.ToLower(r.URL.Query().Get("plugins"))
	pluginNames := strings.Split(pluginsQuery, ",")
	if len(pluginNames) == 1 && pluginNames[0] == "" {
		pluginNames = []string{}
	}

	// Load each plugin's info and check that we can build with it
	var plugins []buildworker.CaddyPlugin
	for _, pluginName := range pluginNames {
		pl, err := loadPluginByName(pluginName)
		if err != nil {
			log.Printf("error loading plugin '%s': %v", pluginName, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// plugin must have at least one release
		if len(pl.Releases) == 0 {
			errStr := fmt.Sprintf("plugin %s (%s) has no releases", pl.ID, pluginName)
			log.Println(errStr)
			http.Error(w, errStr, http.StatusBadRequest)
			return
		}

		// extract only the info the build worker needs;
		// assume latest version of plugin (should be at end of list)
		bwPl := buildworker.CaddyPlugin{
			Package: pl.ImportPath,
			Version: pl.Releases[len(pl.Releases)-1].Version,
			Name:    pl.Name,
			ID:      pl.ID,
		}

		plugins = append(plugins, bwPl)
	}

	// load current Caddy version
	latestCaddy, err := loadLatestCaddyRelease()
	if err != nil {
		log.Printf("error loading latest Caddy release: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// prepare build request for backend
	br := buildworker.BuildRequest{
		Platform: buildworker.Platform{
			OS:   os,
			Arch: arch,
			ARM:  arm,
		},
		BuildConfig: buildworker.BuildConfig{
			CaddyVersion: latestCaddy.Version,
			Plugins:      plugins,
		},
	}

	sendDownload := func(cb CachedBuild) {
		dlFile := cb.ArchiveFilename
		if ofWhat == "signature" {
			dlFile = cb.SignatureFilename
		}
		err := sendFileDownload(filepath.Join(cb.Dir, dlFile), w, r)
		if err != nil {
			log.Println(err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}

	// see if this build is cached; if so, use it
	cacheKey := buildCacheKey(br)
	cb, cached, err := loadCachedBuild(cacheKey)
	if err != nil {
		log.Printf("error checking cache: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cached {
		sendDownload(cb)
		return
	}

	// see if anyone else has already requested a
	// build and is waiting; if so, get in line
	pendingDownloadsMu.Lock()
	waitChan, isPending := pendingDownloads[cacheKey]
	if isPending {
		pendingDownloadsMu.Unlock()
		<-waitChan
		cb, cached, err := loadCachedBuild(cacheKey)
		if err != nil {
			log.Printf("error checking cache: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if cached {
			sendDownload(cb)
			return
		}
	} else {
		waitChan = make(chan struct{})
		pendingDownloads[cacheKey] = waitChan
		pendingDownloadsMu.Unlock()
	}

	// otherwise, request a build and cache it for later

	brBytes, err := json.Marshal(br)
	if err != nil {
		log.Printf("error serializing build request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	req, err := newBuildWorkerRequest("POST", "/build", bytes.NewReader(brBytes))
	if err != nil {
		log.Printf("error creating upstream request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("error connecting upstream: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, err := ioutil.ReadAll(resp.Body)
		var errMsg string
		if err != nil {
			log.Printf("failed to read response body: %v", err)
		}
		if resp.Header.Get("Content-Type") == "application/json" {
			var errInfo BuildError
			err := json.Unmarshal(respBody, &errInfo)
			if err != nil {
				log.Printf("failed to deserialize JSON response: %v", err)
			}
			errMsg = strings.TrimSpace(errInfo.Message)
			// TODO: What to do with the log information?
		} else {
			errMsg = strings.TrimSpace(string(respBody))
		}
		log.Printf("build failed: HTTP %d: %s", resp.StatusCode, errMsg)
		http.Error(w, errMsg, http.StatusBadGateway)
		return
	}

	// read archive and signature files from response
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		log.Printf("failed to parse media type: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		log.Printf("expected multipart response, got: %s", mediaType)
		http.Error(w, "unexpected response from backend", http.StatusBadGateway)
		return
	}

	// construct a new cached build
	cb = CachedBuild{
		Config:    br,
		Timestamp: now,
		CacheKey:  cacheKey,
		Dir:       filepath.Join(BuildCacheDir, cacheKey),
	}

	// read the files from the build worker
	mpr := multipart.NewReader(resp.Body, params["boundary"])
	for {
		p, err := mpr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("error reading multipart body: %v", err)
			http.Error(w, "I/O error", http.StatusBadGateway)
			return
		}

		switch p.FormName() {
		case "archive":
			cb.ArchiveFilename = p.FileName()
		case "signature":
			cb.SignatureFilename = p.FileName()
		}

		fpath := filepath.Join(cb.Dir, p.FileName())
		err = saveFile(p, fpath)
		if err != nil {
			log.Printf("error saving %s to disk: %v", fpath, err)
			http.Error(w, "I/O error", http.StatusBadGateway)
			return
		}
	}

	err = saveCachedBuild(cb)
	if err != nil {
		log.Printf("unable to save cached build to DB: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	pendingDownloadsMu.Lock()
	delete(pendingDownloads, cacheKey)
	pendingDownloadsMu.Unlock()
	close(waitChan)

	sendDownload(cb)
}

// sendFileDownload sends a file down the pipe to w with a
// Content-Disposition such that the client will invoke a
// file download. For HEAD requests, only the headers are
// transmitted.
func sendFileDownload(file string, w http.ResponseWriter, r *http.Request) error {
	//w.Header().Set("Expires", b.Expires.Format(http.TimeFormat)) // TODO - cache invalidation/expiry?

	if r.Method == "HEAD" {
		w.Header().Set("Location", r.URL.String())
		w.WriteHeader(http.StatusOK)
		return nil
	}

	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("error loading cached build: %v", err)
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(file)+`"`)
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, f)
	if err != nil {
		log.Printf("error sending %s down the wire: %v", file, err)
	}
	return nil
}

func buildCacheKey(br buildworker.BuildRequest) string {
	keyStr := fmt.Sprintf("GOOS=%s GOARCH=%s GOARM=%s CGO_ENABLED=%t caddy@%s",
		br.OS, br.Arch, br.ARM, br.Cgo, br.CaddyVersion)

	// sort plugins by import path (we assume they don't change)
	pluginList := PluginList(br.Plugins)
	sort.Sort(pluginList)

	// remove duplicate plugins, just in case
	// (we assume that import paths are unique here)
	for i := 1; i < len(pluginList); i++ {
		if pluginList[i].Package == pluginList[i-1].Package {
			pluginList = append(pluginList[:i], pluginList[i+1:]...)
		}
	}

	// add each plugin and its version, in order, to the key string
	for _, plugin := range pluginList {
		keyStr += fmt.Sprintf(" %s@%s", plugin.ID, plugin.Version)
	}

	// hash the key and return as hex
	hash := sha1.New()
	hash.Write([]byte(keyStr))
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum)
}

// PluginList is a sort.Interface list of plugins.
type PluginList []buildworker.CaddyPlugin

func (l PluginList) Len() int           { return len(l) }
func (l PluginList) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
func (l PluginList) Less(i, j int) bool { return l[i].Package < l[j].Package }

func saveFile(p *multipart.Part, filePath string) error {
	// ensure directory exists
	err := os.MkdirAll(filepath.Dir(filePath), 0755)
	if err != nil {
		return err
	}

	// open output file
	outFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// write to disk
	_, err = io.Copy(outFile, p)
	if err != nil {
		os.Remove(filePath)
		return err
	}

	return nil
}

var pendingDownloads = make(map[string]chan struct{})
var pendingDownloadsMu sync.Mutex

// BuildError is an error from an upstream build.
type BuildError struct {
	Message string
	Log     string
}

// MaxCachedBuilds is the maximum number of builds to cache.
// Minimum effective value is 1. High values are strongly
// recommended for production use.
var MaxCachedBuilds = 1000

// BuildCacheDir is the directory in which to store cached builds.
// Note that this value is used to store the locations of cached
// builds in the database also; changing this value does not update
// the values stored in the database. In other words, a previous
// cache directory would still be accessed when using previously-
// cached builds. So, don't delete old cache directories unless
// the database has been updated by deleting those cached builds.
var BuildCacheDir = "./cache"

// Variables that configure access to the build worker upstream.
var (
	// BuildWorkerUpstream is the base URL to the upstream build worker.
	// It should include a scheme, host, and port (if non-standard)
	// and no path (no trailing slash).
	BuildWorkerUpstream = "http://localhost:2017"

	// BuildWorkerClientID is the username/ID for the build worker.
	BuildWorkerClientID string

	// BuildWorkerClientKey is the password/key for the build worker.
	BuildWorkerClientKey string
)
