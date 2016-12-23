package devportal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/buildworker"
)

func deployCaddyHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	account := r.Context().Value(CtxKey("account")).(AccountInfo)
	if !account.CaddyMaintainer {
		http.Error(w, "only maintainers may deploy Caddy", http.StatusForbidden)
		return
	}

	type DeployRequest struct {
		CaddyVersion string `json:"caddy_version"`
	}
	var info DeployRequest
	err := json.NewDecoder(r.Body).Decode(&info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if info.CaddyVersion == "" {
		// blah blah blah
	}

	// TODO: is there already a release at this version? if so, reject...?
	// should that be checked by release-caddy as well?

	body, err := json.Marshal(info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req, err := newBuildWorkerRequest("POST", "/deploy-caddy", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode >= 400 {
			bodyText, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("failed to read response body: %v", err)
			}
			resp.Body.Close()
			log.Printf("deploy failed: status %d: %s, error: %v", resp.StatusCode, bodyText, err)
			return
		}
		err = saveCaddyRelease(CaddyRelease{
			Timestamp:  now,
			Version:    info.CaddyVersion,
			ReleasedBy: account.ID,
		})
		if err != nil {
			log.Printf("deploy succeeded but failed to save: %v", err)
		}
	}()

	w.WriteHeader(http.StatusAccepted)
}

func deployPluginHandler(w http.ResponseWriter, r *http.Request) {
	// get information from request
	type DeployRequest struct {
		PluginID      string `json:"plugin_id"`
		PluginVersion string `json:"plugin_version"`
	}
	var info DeployRequest
	err := json.NewDecoder(r.Body).Decode(&info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load plugin from database
	pl, err := loadPlugin(info.PluginID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// make sure user has permission to deploy this plugin
	account := r.Context().Value(CtxKey("account")).(AccountInfo)
	if pl.OwnerAccountID != account.ID {
		http.Error(w, "your account is not unauthorized to deploy this plugin", http.StatusForbidden)
		return
	}

	// reject if there is already a release at this version
	for _, rel := range pl.Releases {
		if rel.Version == info.PluginVersion {
			http.Error(w, "plugin already released at that version", http.StatusConflict)
			return
		}
	}

	// initiate deploy
	err = deployPlugin(pl.ID, pl.ImportPath, info.PluginVersion, account)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	// if user is already logged in, redirect them to dashboard
	if _, err := getLoggedInAccount(r); err == nil {
		http.Redirect(w, r, "/account/dashboard", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, "/Users/matt/Sites/newcaddy/account/login.html")
}

var (
	supportedPlatforms           []buildworker.Platform
	supportedPlatformsLastUpdate time.Time
	supportedPlatformsMu         sync.RWMutex
)

// updateSupportedPlatforms gets the latest supported platforms
// from the upstream build worker and updates the list cached here.
func updateSupportedPlatforms() error {
	req, err := newBuildWorkerRequest("GET", "/supported-platforms", nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	var platforms []buildworker.Platform
	err = json.NewDecoder(resp.Body).Decode(&platforms)
	if err != nil {
		return err
	}

	supportedPlatformsMu.Lock()
	supportedPlatforms = platforms
	supportedPlatformsLastUpdate = time.Now()
	supportedPlatformsMu.Unlock()

	return nil
}

func populateDownloadPage(w http.ResponseWriter, r *http.Request) {
	type DownloadPageInfo struct {
		Latest    CaddyRelease           `json:"latest_caddy"`
		Plugins   []Plugin               `json:"plugins"`
		Platforms []buildworker.Platform `json:"platforms"`
	}
	supportedPlatformsMu.RLock()
	lastUpdate := supportedPlatformsLastUpdate
	supportedPlatformsMu.RUnlock()
	if time.Since(lastUpdate) > 1*time.Hour {
		err := updateSupportedPlatforms()
		if err != nil {
			log.Printf("download-page: updating supported platforms: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	supportedPlatformsMu.RLock()
	dlinfo := DownloadPageInfo{Platforms: supportedPlatforms}
	supportedPlatformsMu.RUnlock()

	rel, err := loadLatestCaddyRelease()
	if err != nil {
		log.Printf("download-page: loading latest Caddy release: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dlinfo.Latest = rel

	plugins, err := loadAllPlugins()
	if err != nil {
		log.Printf("download-page: loading all plugins: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, plugin := range plugins {
		if len(plugin.Releases) == 0 {
			continue
		}
		plugin.Releases = plugin.Releases[len(plugin.Releases)-1:]
		dlinfo.Plugins = append(dlinfo.Plugins, plugin)
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(dlinfo)
	if err != nil {
		log.Printf("download-page: %v", err)
		return
	}
}
