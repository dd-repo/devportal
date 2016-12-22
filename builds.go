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
	req, err := http.NewRequest("POST", "http://localhost:2017/deploy-plugin", bytes.NewReader(j))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("dev", "happypass123") // TODO: get from environment

	go func() {
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

			// TODO: notify account that requested the deploy of the failure

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
		}

		// TODO: Notify account of success
	}()

	return nil
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	vars := mux.Vars(r)
	os := vars["os"]
	arch := vars["arch"]
	var arm string
	if strings.HasPrefix(arch, "arm") {
		arm = arch[3:]
		arch = arch[:3]
	}

	// TODO: check that we support the platform

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
		err := sendFileDownload(filepath.Join(cb.Dir, cb.ArchiveFilename), w)
		if err != nil {
			log.Println(err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}

	// see if this build is cached
	cacheKey := buildCacheKey(br)
	cb, ok, err := loadCachedBuild(cacheKey)
	if err != nil {
		log.Printf("error checking cache: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if ok {
		// build is cached! use it.
		sendDownload(cb)
		return
	}

	// otherwise, request a build and cache it for later

	brBytes, err := json.Marshal(br)
	if err != nil {
		log.Printf("error serializing build request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	fmt.Println("BUILD REQUEST:", string(brBytes))

	req, err := http.NewRequest("POST", "http://localhost:2017/build", bytes.NewReader(brBytes))
	if err != nil {
		log.Printf("error creating upstream request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("dev", "happypass123") // TODO: get from environment

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
		Dir:       filepath.Join(cacheDir, cacheKey),
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

	sendDownload(cb)
}

// sendFileDownload sends a file down the pipe to w with a
// Content-Disposition such that the client will invoke a
// file download.
func sendFileDownload(file string, w http.ResponseWriter) error {
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

	fmt.Println(keyStr) // TODO: temp

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

const cacheDir = "cache"

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

func signatureHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("signature handler", mux.Vars(r)["os"], mux.Vars(r)["arch"])
	// TODO
}

// BuildError is an error from an upstream build.
type BuildError struct {
	Message string
	Log     string
}
