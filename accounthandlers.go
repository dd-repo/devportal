package devportal

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/boltdb/bolt"
)

// TODO: CSRF protection

func login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.Form.Get("email")) // required
	password := r.Form.Get("password")              // required

	// email is not case-sensitive
	emailKey := []byte(strings.ToLower(email))

	// get account ID to load account
	var acctID string
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("index:emailsToAccounts"))
		acctID = string(b.Get(emailKey))
		return nil
	})

	if acctID == "" {
		log.Printf("login: no account found for '%s'", email)
		http.Error(w, "Unable to log in", http.StatusUnauthorized)
		return
	}

	// load account info
	acc, err := loadAccount(acctID)
	if err != nil {
		log.Println("login: error loading from DB:", err)
		http.Error(w, "Unable to log in", http.StatusUnauthorized)
		return
	}

	// check passwords
	if assertPasswordsMatch(password, acc.Password, acc.Salt) != nil {
		log.Printf("login: bad credentials for account: %s", email)
		http.Error(w, "Unknown email and password combination", http.StatusUnauthorized)
		return
	}
	if acc.VerifiedDate.IsZero() {
		http.Error(w, "login: account is not confirmed", http.StatusForbidden)
		return
	}

	// authenticated
	sess, _ := cookies.Get(r, "user") // OK to ignore error; new session still returned
	sess.Values["id"] = acctID
	err = sess.Save(r, w)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Successfully authenticated: %s\n", acc.Email)
}

func logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := cookies.Get(r, "user")
	if _, ok := sess.Values["id"]; !ok {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}
	sess.Options.MaxAge = -1
	err := sess.Save(r, w)
	if err != nil {
		log.Println(err)
		http.Error(w, "Saving session: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func listPlugins(w http.ResponseWriter, r *http.Request) {
	// parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// get list of plugins
	infos, _, _, _, err := getPluginInfos(r, false, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// send to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(infos)
}

// getPluginInfos returns the list of plugins, along with some values
// on the request: repo, version, and subfolder (in that order).
func getPluginInfos(r *http.Request, allowCache, requireSubfolder bool) ([]Plugin, string, string, string, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, "", "", "", err
	}

	repo := strings.TrimSpace(r.Form.Get("clone_url"))
	version := strings.TrimSpace(r.Form.Get("version"))
	subfolder := strings.TrimSpace(r.Form.Get("subfolder"))
	if repo == "" {
		return nil, "", "", "", fmt.Errorf("missing required field(s)")
	}

	// assume root of repository if no subfolder given, and if one is required
	if requireSubfolder && subfolder == "" {
		subfolder = "."
	}

	infos, err := allPluginInfos(repo, version, subfolder, allowCache)
	return infos, repo, version, subfolder, err
}

// TODO: This should be an actual web page, not an API endpoint...
func confirmAccount(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.Form.Get("email"))
	acctID := strings.TrimSpace(r.Form.Get("acct"))
	if email == "" || acctID == "" {
		http.Error(w, "Missing required field(s)", http.StatusBadRequest)
		return
	}

	acc, err := loadAccount(acctID)
	if err != nil {
		log.Printf("confirm-account: error loading from database: %v", err)
		// fail silently to avoid leaking whether email address is registered
		w.WriteHeader(http.StatusOK)
		return
	}
	if !acc.VerifiedDate.IsZero() {
		log.Printf("confirm-account: Account already confirmed: %s (%s)", acctID, email)
		w.WriteHeader(http.StatusOK) // fail silently to avoid leaking email address; not critical
		return
	}

	// mark the account as verified
	acc.VerifiedDate = time.Now()

	err = saveAccount(acc)
	if err != nil {
		log.Printf("confirm-account: error updating database: %v", err)
		http.Error(w, "Unable to confirm account", http.StatusInternalServerError)
		return
	}

	log.Printf("confirm-account: Account confirmed: %s", acctID)
}

func registerAccount(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// validate input values
	email := strings.TrimSpace(r.Form.Get("email")) // required
	password := r.Form.Get("password")              // required
	emailKey := strings.ToLower(email)
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}
	if len(password) < MinPasswordLength {
		http.Error(w, fmt.Sprintf("Password must be at least %d characters", MinPasswordLength), http.StatusBadRequest)
		return
	}
	if !isUnique("index:emailsToAccounts", emailKey) {
		log.Printf("register-account: Email address already registered: %s", email)
		w.WriteHeader(http.StatusOK) // fail silently to obscure whether email is used
		return
	}

	// generate unique ID for new account
	acctID, err := uniqueID("accounts")
	if err != nil {
		log.Printf("register-account: No unique IDs available as account ID (for %s)", email)
		http.Error(w, "No unique IDs available; try again", http.StatusInternalServerError)
		return
	}

	// salt and hash the password
	hashedPass, salt, err := createPassword(password)
	if err != nil {
		log.Printf("register-account: could not create password for %s: %v", email, err)
		// don't leak details
		http.Error(w, "Error creating account", http.StatusInternalServerError)
		return
	}

	// generate API key
	const apiKeySizeInBytes = 16
	apiKey := make([]byte, apiKeySizeInBytes)
	_, err = io.ReadFull(rand.Reader, apiKey)
	if err != nil {
		log.Printf("register-account: Could not generate API key: %v", err)
		http.Error(w, "Error creating account", http.StatusInternalServerError)
		return
	}

	acc := AccountInfo{
		ID:               acctID,
		Email:            email,
		Password:         hashedPass,
		Salt:             salt,
		APIKey:           apiKey,
		RegistrationDate: time.Now(),
		CaddyMaintainer:  true, // TODO: temporary!
	}

	err = saveAccount(acc)
	if err != nil {
		log.Printf("register-account: could not save account %s to database: %v", acctID, err)
		http.Error(w, "Error creating account", http.StatusInternalServerError)
		return
	}

	log.Printf("Registered new account: %#v\n", acc)

	// TODO: send confirmation email
}

func registerPlugin(w http.ResponseWriter, r *http.Request) {
	infos, repo, version, subfolder, err := getPluginInfos(r, true, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pkg := strings.TrimSpace(r.Form.Get("import_path"))
	name := strings.TrimSpace(strings.ToLower(r.Form.Get("plugin_name")))
	pluginType := r.Form.Get("plugin_type")
	if pkg == "" || name == "" || pluginType == "" {
		http.Error(w, "missing required field(s)", http.StatusBadRequest)
		return
	}
	if version == "" {
		version = "master"
	}

	// ensure name is unique
	if !isUnique("index:namesToPlugins", name) {
		http.Error(w, "a plugin named '"+name+"' is already published", http.StatusConflict)
		return
	}

	// TODO: ensure import path is unique! (build worker can't distinguish
	// between different plugins in the same package; it just imports the
	// whole package... multiple plugins may be in a package but only one
	// can be published or 'plugged in' by the user, the rest would just
	// come with it)

	// select the plugin from the list that matches the
	// name and type, so we can fill in its information.
	var pl Plugin
	for _, info := range infos {
		if info.Name == name && info.Type.ID == pluginType {
			pl = info
		}
	}

	// generate unique ID for this plugin
	pl.ID, err = uniqueID("plugins")
	if err != nil {
		log.Printf("register-plugin: No unique IDs available as plugin ID (for %s)", repo)
		http.Error(w, "No unique IDs available; try again", http.StatusInternalServerError)
		return
	}

	// fill in the rest of the information
	account := r.Context().Value(CtxKey("account")).(AccountInfo)
	pl.OwnerAccountID = account.ID
	pl.ImportPath = pkg
	pl.SourceRepo = repo
	pl.Subfolder = subfolder

	// save plugin to database
	err = savePlugin(pl)
	if err != nil {
		log.Printf("register-plugin: could not save plugin %s to database: %v", pl.ID, err)
		http.Error(w, "Error saving plugin", http.StatusInternalServerError)
		return
	}

	log.Printf("Registered plugin %s (%s) (user %s: %s); deploying now",
		pl.ID, pl.ImportPath, account.ID, account.Email)

	// initiate plugin deploy
	err = deployPlugin(pl.ID, pl.ImportPath, version, account)
	if err != nil {
		log.Printf("register-plugin: could not initiate deploy: %v", err)
		http.Error(w, "Error deploying plugin", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
