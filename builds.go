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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
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

func notifyUser(account AccountInfo, level NotifLevel, title, body string) error {
	if title == "" {
		return fmt.Errorf("notification title cannot be empty")
	}

	err := saveNewNotification(account.ID, level, title, body)
	if err != nil {
		return fmt.Errorf("saving notification: %v", err)
	}

	vals := url.Values{}
	vals.Set("email", account.Email)
	vals.Set("account", account.ID)
	vals.Set("level", strconv.Itoa(int(level)))
	qs := vals.Encode()

	unsubURL := fmt.Sprintf("https://caddyserver.com/account/unsubscribe?%s", qs)
	emailBody := fmt.Sprintf("%s\n\nYou received this email because your account on the Caddy website "+
		"is configured to receive emails for %s notifications.\n"+
		"To stop receiving %s notifications, click here to unsubscribe: %s",
		body, NotifLevelText(level), NotifLevelText(level), unsubURL)

	if (level == NotifInfo && account.EmailNotifyInfo) ||
		(level == NotifSuccess && account.EmailNotifySuccess) ||
		(level == NotifWarn && account.EmailNotifyWarn) ||
		(level == NotifError && account.EmailNotifyError) {
		err = sendEmail(account.Name, account.Email, title, emailBody)
		if err != nil {
			return fmt.Errorf("sending notification: %v", err)
		}
	}

	return nil
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
		var deployErr error
		var buildErrInfo struct {
			Message string
			Log     string
		}

		// notify account of success or failure
		defer func() {
			plugin, err := loadPlugin(pluginID)
			if err != nil {
				log.Printf("Loading plugin after deploy: %v", err)
				return
			}
			if deployErr != nil {
				title := fmt.Sprintf("%s: Deploy of %s failed", plugin.Name, version)
				body := fmt.Sprintf("The build worker was unable to deploy %s at version '%s' because of a network "+
					"or compiler error, or your plugin failed a check. The log is attached.\n\n```\n%s\n%s\n\n%s\n```",
					plugin.Name, version, deployErr, buildErrInfo.Message, buildErrInfo.Log)
				err = notifyUser(account, NotifError, title, body)
				if err != nil {
					log.Printf("Error notifying user: %v", err)
				}
				return
			}
			err = notifyUser(account, NotifSuccess, fmt.Sprintf("%s: Successful deploy of %s", plugin.Name, version), "")
			if err != nil {
				log.Printf("Notifying user after deploy: %v", err)
				return
			}
			log.Printf("plugin deploy succeeded: %s@%s (plugin ID: %s)", plugin.Name, version, plugin.ID)
		}()

		// send blocking request upstream to build worker
		resp, deployErr := http.DefaultClient.Do(req)
		if deployErr != nil {
			log.Printf("plugin deploy failed, network error: %v", deployErr)
			return
		}
		defer resp.Body.Close()

		// handle any error with the build
		if resp.StatusCode >= 400 {
			bodyText, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("failed to read response body: %v", err)
			}
			log.Printf("plugin deploy failed: HTTP %d (plugin ID: %s; version: %s)", resp.StatusCode, pluginID, version)
			deployErr = fmt.Errorf("plugin deploy failed")
			json.Unmarshal(bodyText, &buildErrInfo)
			log.Printf("[DEPLOY ERROR] %s >>>>>>>>>>>>>\n%s\n<<<<<<<<<<<<<\n",
				buildErrInfo.Message, strings.TrimSpace(buildErrInfo.Log))
			return
		}

		// if successful, save the release to the DB
		deployErr = savePluginRelease(pluginID, PluginRelease{
			Timestamp:    now,
			Version:      version,
			CaddyVersion: caddyRel.Version,
		})
		if deployErr != nil {
			log.Printf("plugin deploy succeeded but failed to save: %v (plugin ID: %s)", err, pluginID)
			return
		}

		// evict cached builds with this plugin; not really necessary except
		// if the plugin is deployed at a branch, since the cache key won't
		// be different, since branch names don't change while the ref does.
		// to avoid serving stale content, we just purge these cached builds.
		err = evictBuildsFromCache(pluginID, version, "")
		if err != nil {
			log.Printf("evicting affected builds from cache: %v", err)
			return
		}
	}()

	return nil
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	produceDownload(ofArchive, w, r)
}

func signatureHandler(w http.ResponseWriter, r *http.Request) {
	produceDownload(ofSignature, w, r)
}

func produceDownload(ofWhat string, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Expose-Headers", "Location")

	now := time.Now().UTC()

	// get fundamental os/arch data from request
	vars := mux.Vars(r)
	os := vars["os"]
	arch := vars["arch"]
	var arm string
	if strings.HasPrefix(arch, "arm") && arch != "arm64" {
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

	// count this download if it's a GET request for an actual copy of Caddy
	if r.Method == "GET" && ofWhat == ofArchive {
		err := updateCounts(br)
		if err != nil {
			log.Printf("error updating counts in DB: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}

	// sendDownload sends the download of the build cached with cb
	// to the client. If rebuildIfCacheErr is true, a missing cache
	// file on the disk will simply cause this function to return
	// true. If this function returns true, try rebuilding as if it
	// was never in the cache.
	sendDownload := func(cb CachedBuild, rebuildIfCacheErr bool) bool {
		dlFile := cb.ArchiveFilename
		if ofWhat == ofSignature {
			if cb.SignatureFilename == "" {
				log.Printf("[INFO] build signature '%s/%s' unavailable", cb.Dir, cb.SignatureFilename)
				http.Error(w, "no build signature available", http.StatusNotFound)
				return false
			}
			dlFile = cb.SignatureFilename
		}
		err := sendFileDownload(filepath.Join(cb.Dir, dlFile), w, r)
		if err != nil {
			log.Printf("[ERROR] %v", err)
			if _, ok := err.(cacheError); ok && rebuildIfCacheErr {
				log.Printf("[INFO] evicting %s from cache and re-building", cb.Dir)
				err := deleteCachedBuild(cb)
				if err != nil {
					log.Printf("[ERROR] evicting build cache entry: %v", err)
				}
				return true
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return false
	}

	retryBuildIfCacheErr := true

tryBuild:

	// see if this build is cached; if so, use it
	cacheKey := buildCacheKey(br)
	cb, cached, err := loadCachedBuild(cacheKey)
	if err != nil {
		log.Printf("error checking cache: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cached {
		retry := sendDownload(cb, retryBuildIfCacheErr)
		if retry {
			retryBuildIfCacheErr = false // avoid infinte loop just in case
			goto tryBuild
		}
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
			sendDownload(cb, false)
			return
		}
	} else {
		// if nobody else has it, we own the lock on this build
		waitChan = make(chan struct{})
		pendingDownloads[cacheKey] = waitChan
		pendingDownloadsMu.Unlock()
	}

	// request a build and cache it for later

	releaseLock := func() {
		// let anyone waiting on this build know that they can have it;
		// this must also be called on error, otherwise requests hang
		pendingDownloadsMu.Lock()
		delete(pendingDownloads, cacheKey)
		pendingDownloadsMu.Unlock()
		close(waitChan)
	}

	brBytes, err := json.Marshal(br)
	if err != nil {
		releaseLock()
		log.Printf("error serializing build request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	req, err := newBuildWorkerRequest("POST", "/build", bytes.NewReader(brBytes))
	if err != nil {
		releaseLock()
		log.Printf("error creating upstream request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		releaseLock()
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
			log.Printf("[BUILD ERROR] %s >>>>>>>>>>>>>\n%s\n<<<<<<<<<<<<<\n",
				errMsg, strings.TrimSpace(errInfo.Log))
		} else {
			errMsg = strings.TrimSpace(string(respBody))
		}
		releaseLock()
		log.Printf("build failed: HTTP %d: %s", resp.StatusCode, errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	// read archive and signature files from response
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		releaseLock()
		log.Printf("failed to parse media type: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		releaseLock()
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
			releaseLock()
			log.Printf("error reading multipart body: %v", err)
			http.Error(w, "I/O error", http.StatusBadGateway)
			return
		}

		switch p.FormName() {
		case ofArchive:
			cb.ArchiveFilename = p.FileName()
		case ofSignature:
			cb.SignatureFilename = p.FileName()
		}

		fpath := filepath.Join(cb.Dir, p.FileName())
		err = saveFile(p, fpath)
		if err != nil {
			releaseLock()
			log.Printf("error saving %s to disk: %v", fpath, err)
			http.Error(w, "I/O error", http.StatusBadGateway)
			return
		}
	}

	err = saveCachedBuild(cb)
	if err != nil {
		releaseLock()
		log.Printf("unable to save cached build to DB: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	releaseLock()

	sendDownload(cb, false)
}

// cacheError indicates an error opening a file from the cache.
type cacheError error

// sendFileDownload sends a file down the pipe to w with a
// Content-Disposition such that the client will invoke a
// file download. For HEAD requests, only the headers are
// transmitted. If the error is of type cacheError, then
// it means the cached file could not be opened.
func sendFileDownload(file string, w http.ResponseWriter, r *http.Request) error {
	f, err := os.Open(file)
	if err != nil {
		errReturn := fmt.Errorf("error loading cached build: %v", err)
		if os.IsNotExist(err) {
			return cacheError(errReturn)
		}
		return errReturn
	}
	defer f.Close()

	// we do this after opening the file to ensure it exists and that we're able to transmit
	if r.Method == "HEAD" {
		w.Header().Set("Location", r.URL.String())
		w.WriteHeader(http.StatusOK)
		return nil
	}

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

func updateCounts(br buildworker.BuildRequest) error {
	serialized := []byte(br.Serialize())
	return db.Update(func(tx *bolt.Tx) error {
		var aggregates Counts
		b := tx.Bucket([]byte("counts"))
		agg := b.Get([]byte("aggregates"))
		if agg == nil {
			aggregates.ByArch = make(map[string]int)
			aggregates.ByOS = make(map[string]int)
			aggregates.ByVersion = make(map[string]int)
			aggregates.NumPlugins = make(map[int]int)
		} else {
			err := gobDecode(agg, &aggregates)
			if err != nil {
				return err
			}
		}

		// update aggregate counts
		aggregates.Total++
		aggregates.ByOS[br.Platform.OS]++
		aggregates.ByArch[br.Platform.Arch]++
		aggregates.ByVersion[br.BuildConfig.CaddyVersion]++
		aggregates.NumPlugins[len(br.BuildConfig.Plugins)]++
		aggregates.LastDownload = time.Now().UTC()
		aggBytes, err := gobEncode(aggregates)
		if err != nil {
			return err
		}
		err = b.Put([]byte("aggregates"), aggBytes)
		if err != nil {
			return err
		}

		// update download count for each plugin
		pluginBucket := tx.Bucket([]byte("plugins"))
		for _, plugin := range br.BuildConfig.Plugins {
			pluginBytes := pluginBucket.Get([]byte(plugin.ID))
			var pl Plugin
			err := gobDecode(pluginBytes, &pl)
			if err != nil {
				return err
			}
			pl.DownloadCount++
			pluginBytes, err = gobEncode(pl)
			if err != nil {
				return err
			}
			err = pluginBucket.Put([]byte(plugin.ID), pluginBytes)
			if err != nil {
				return err
			}
		}

		// add this build configuration to the log if it's not already seen,
		// and increment its download count.
		all, err := b.CreateBucketIfNotExists([]byte("all"))
		if err != nil {
			return err
		}
		var updatedCount int
		countVal := all.Get(serialized)
		if countVal == nil {
			updatedCount = 1
		} else {
			err := gobDecode(countVal, &updatedCount)
			if err != nil {
				return err
			}
			updatedCount++
		}
		newCount, err := gobEncode(updatedCount)
		if err != nil {
			return err
		}
		return all.Put(serialized, newCount)
	})
}

// PluginList is a sort.Interface list of plugins that sorts plugins
// by PACKAGE IMPORT PATH, not by name.
type PluginList []buildworker.CaddyPlugin

func (l PluginList) Len() int           { return len(l) }
func (l PluginList) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
func (l PluginList) Less(i, j int) bool { return l[i].Package < l[j].Package }

// PluginsByName is a sort.Interface list of plugins that sorts plugins
// by PLUGIN NAME, not package import path.
type PluginsByName []Plugin

func (l PluginsByName) Len() int           { return len(l) }
func (l PluginsByName) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
func (l PluginsByName) Less(i, j int) bool { return l[i].Name < l[j].Name }

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
var MaxCachedBuilds = 1500

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

const (
	ofArchive   = "archive"
	ofSignature = "signature"
)
