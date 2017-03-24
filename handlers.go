package devportal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/buildworker"
	humanize "github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
)

func templatedPage(w http.ResponseWriter, r *http.Request) {
	renderTemplatedPage(w, r, r.URL.Path)
}

func accountTpl(templateFile string) http.HandlerFunc {
	return authHandler(func(w http.ResponseWriter, r *http.Request) {
		renderTemplatedPage(w, r, templateFile)
	}, unauthPage)
}

func accountTplPluginOwner(templateFile string) http.HandlerFunc {
	return authHandler(pluginOwner(func(w http.ResponseWriter, r *http.Request) {
		renderTemplatedPage(w, r, templateFile)
	}), unauthPage)
}

func docsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: This could be cached on the order of minutes
	// in order to reduce read stress on the DB.
	plugins, err := loadAllPlugins("")
	if err != nil {
		log.Printf("docs handler: loading plugins: %v", err)
	}
	pluginMap := make(map[string][]Plugin)
	for _, plugin := range plugins {
		pluginMap[plugin.Type.CategoryTitle] = append(pluginMap[plugin.Type.CategoryTitle], plugin)
	}
	r = r.WithContext(context.WithValue(r.Context(), CtxKey("plugin_map"), pluginMap))

	// see if this request is asking for a page with information about a plugin
	pluginName := mux.Vars(r)["pluginName"]
	plugin, err := loadPluginByName(pluginName)
	if err == nil {
		// serve page with plugin details
		r = r.WithContext(context.WithValue(r.Context(), CtxKey("plugin"), plugin))
		renderTemplatedPage(w, r, "/docs/_plugin.html")
		return
	} else if _, ok := err.(noPluginWithName); ok {
		// error is okay, just means not a plugin; serve static file
		renderTemplatedPage(w, r, r.URL.Path)
		return
	}

	// some other error
	log.Printf("loading docs page for plugin %s: %v", pluginName, err)
	http.Error(w, "error loading page", http.StatusInternalServerError)
	return
}

func pluginOwner(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// load the plugin from the path var in the request
		pluginID := mux.Vars(r)["id"]
		pl, err := loadPlugin(pluginID)
		if err != nil {
			log.Printf("error loading plugin %s: %v", pluginID, err)
			http.Error(w, "error loading plugin "+pluginID, http.StatusNotFound)
			return
		}

		// load the account from the context (should already be authenticated)
		// to ensure that account is authorized
		account := r.Context().Value(CtxKey("account")).(AccountInfo)
		if pl.OwnerAccountID != account.ID {
			log.Printf("account %s is not authorized to access plugin %s", account.ID, pluginID)
			http.Error(w, "account not authorized to access plugin "+pluginID, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKey("plugin"), pl)

		h.ServeHTTP(w, r.WithContext(ctx))
	}
}

func deployCaddyHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	account := r.Context().Value(CtxKey("account")).(AccountInfo)
	if !account.CaddyMaintainer {
		log.Printf("account %s tried to deploy Caddy but is not a maintainer", account.ID)
		http.Error(w, "only maintainers may deploy Caddy", http.StatusForbidden)
		return
	}

	type DeployRequest struct {
		CaddyVersion string `json:"caddy_version"`
	}
	var depreq DeployRequest
	err := json.NewDecoder(r.Body).Decode(&depreq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if depreq.CaddyVersion == "" {
		http.Error(w, "missing version", http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(depreq)
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
			Version:    depreq.CaddyVersion,
			ReleasedBy: account.ID,
		})
		if err != nil {
			log.Printf("deploy succeeded but failed to save: %v", err)
		}

		// clear the cache of any builds that are based on this same
		// version of Caddy; this is helpful if deploying at a branch
		// name where the underlying commit is different but the
		// cache key is the same because the branch name is the same.
		err = evictBuildsFromCache("", "", depreq.CaddyVersion)
		if err != nil {
			log.Printf("evicting affected builds from cache: %v", err)
			return
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
	var depreq DeployRequest
	err := json.NewDecoder(r.Body).Decode(&depreq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load plugin from database
	pl, err := loadPlugin(depreq.PluginID)
	if err != nil {
		log.Printf("deploy plugin: error loading plugin from database: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// make sure user has permission to deploy this plugin
	account := r.Context().Value(CtxKey("account")).(AccountInfo)
	if pl.OwnerAccountID != account.ID {
		log.Printf("deploy plugin: account %s is not authorized to deploy plugin %s", account.ID, pl.ID)
		http.Error(w, "your account is not unauthorized to deploy this plugin", http.StatusForbidden)
		return
	}

	// analyze repo to 1) ensure that all plugin names are unique within repo,
	// and 2) that the plugin exists with the same name and type as before
	infos, err := allPluginInfos(pl.SourceRepo, depreq.PluginVersion, "", true)
	if err != nil {
		log.Printf("deploy plugin: error getting plugin infos in %s: %v", pl.SourceRepo, err)
		http.Error(w, "error checking plugin repository; ensure repo and version are correct", http.StatusBadRequest)
		return
	}
	if duplicate, dupName := anyDuplicatePluginName(infos); duplicate {
		log.Printf("deploy plugin: repository %s has a repeated plugin name: %s", pl.SourceRepo, dupName)
		http.Error(w, "plugin name is not unique within repository", http.StatusBadRequest)
		return
	}
	var found bool
	for _, info := range infos {
		if info.Name == pl.Name {
			found = true
			if info.Type.ID != pl.Type.ID {
				log.Printf("deploy plugin: plugin %s has changed types: from %s to %s",
					pl.ID, pl.Type.ID, info.Type.ID)
				http.Error(w, "plugin has changed types", http.StatusBadRequest)
				return
			}
		}
	}
	if !found {
		log.Printf("deploy plugin: plugin %s seems to have disappeared from repo %s", pl.ID, pl.SourceRepo)
		http.Error(w, "plugin not found in source repo", http.StatusBadRequest)
		return
	}

	// initiate deploy
	err = deployPlugin(pl.ID, pl.ImportPath, depreq.PluginVersion, account)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func loggedInRedir(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := getLoggedInAccount(r); err == nil {
			http.Redirect(w, r, "/account/dashboard", http.StatusSeeOther)
			return
		}
		h.ServeHTTP(w, r)
	}
}

func staticPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(siteRoot, r.URL.Path))
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	// if user is already logged in, redirect them to dashboard
	if _, err := getLoggedInAccount(r); err == nil {
		http.Redirect(w, r, "/account/dashboard", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, filepath.Join(siteRoot, r.URL.Path))
}

func registerPage(w http.ResponseWriter, r *http.Request) {
	// if user is already logged in, redirect them to dashboard
	if _, err := getLoggedInAccount(r); err == nil {
		http.Redirect(w, r, "/account/dashboard", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, filepath.Join(siteRoot, r.URL.Path))
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
	type PluginWithOwner struct {
		Plugin
		OwnerName  string
		LastUpdate string // newest of meta or most recent release
		Required   bool   // TODO: add an HTTP server type to the list and mark it as required
	}
	type DownloadPageInfo struct {
		Latest    CaddyRelease           `json:"latest_caddy"`
		Plugins   []PluginWithOwner      `json:"plugins"`
		Platforms []buildworker.Platform `json:"platforms"`
	}

	// get the list of supported platforms, but
	// first update the list if it's been a while
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

	// get the current version of Caddy
	rel, err := loadLatestCaddyRelease()
	if err != nil {
		log.Printf("download-page: loading latest Caddy release: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dlinfo.Latest = rel

	// load all the plugins
	plugins, err := loadAllPlugins("")
	if err != nil {
		log.Printf("download-page: loading all plugins: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, plugin := range plugins {
		// skip plugins that aren't released or are unpublished
		if len(plugin.Releases) == 0 || plugin.Unpublished {
			continue
		}
		ownerAcct, err := loadAccount(plugin.OwnerAccountID)
		if err != nil {
			log.Printf("download-page: loading plugin (ID %s) owner information (ID %s): %v", plugin.ID, plugin.OwnerAccountID, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		plugin.Releases = plugin.Releases[len(plugin.Releases)-1:] // reveal only latest release to save bandwidth
		plugin.OwnerAccountID = ""                                 // strip owner ID
		plugin.DownloadCount = -1                                  // strip download count
		lastUpdate := plugin.Updated
		if plugin.Releases[0].Timestamp.After(lastUpdate) {
			lastUpdate = plugin.Releases[0].Timestamp
		}
		dlinfo.Plugins = append(dlinfo.Plugins, PluginWithOwner{
			Plugin:     plugin,
			OwnerName:  ownerAcct.Name,
			LastUpdate: humanize.Time(lastUpdate),
		})
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(dlinfo)
	if err != nil {
		log.Printf("download-page: %v", err)
		return
	}
}
