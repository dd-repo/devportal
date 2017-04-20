package devportal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
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
	db.View(func(tx *bolt.Tx) error {
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

func resetPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.Form.Get("email")) // required
	token := r.Form.Get("token")
	password := r.Form.Get("password")

	// email is not case-sensitive
	emailKey := []byte(strings.ToLower(email))

	// get account ID to load account
	var acctID string
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("index:emailsToAccounts"))
		acctID = string(b.Get(emailKey))
		return nil
	})
	if acctID == "" {
		log.Printf("reset-password: no account with email: %s", email)
		w.WriteHeader(http.StatusOK) // don't reveal whether an account has this email address
		return
	}

	// load account info
	acc, err := loadAccount(acctID)
	if err != nil {
		log.Println("reset-password: error loading from DB:", err)
		http.Error(w, "Unable to reset password", http.StatusInternalServerError)
		return
	}

	if token == "" && password == "" {
		// step 1: requesting a token

		acc.PasswordReset = ResetToken{
			Token:   randString(18),
			Created: time.Now().UTC(),
		}

		err := saveAccount(acc)
		if err != nil {
			log.Printf("reset-password (step 1): error saving account with reset token: %v", err)
			http.Error(w, "Unable to reset password", http.StatusInternalServerError)
			return
		}

		val := url.Values{
			"email": []string{acc.Email},
			"token": []string{acc.PasswordReset.Token},
		}
		resetPage := "https://caddyserver.com/account/reset-password"
		repl := strings.NewReplacer(
			"{name}", acc.Name,
			"{reset_page}", resetPage,
			"{reset_link}", fmt.Sprintf("%s?%s", resetPage, val.Encode()),
			"{token}", acc.PasswordReset.Token)
		body := repl.Replace(resetMsg)

		err = sendEmail(acc.Name, acc.Email, "Reset your Caddy Developer password", body)
		if err != nil {
			log.Printf("reset-password: sending token email to %s (account %s): %v", acc.Email, acc.ID, err)
			http.Error(w, "Error resetting password", http.StatusInternalServerError)
			return
		}

		log.Printf("reset-password: Sent password reset email for %s (account %s)\n", acc.Email, acc.ID)
	} else {
		// step 2: setting new password

		if acc.PasswordReset.Token == "" || acc.PasswordReset.Expired() {
			log.Printf("reset-password: attempt to reset password for %s (account %s) is unauthorized, token: %+v",
				acc.Email, acc.ID, acc.PasswordReset)
			http.Error(w, "Unauthorized to attempt reset", http.StatusUnauthorized)
			return
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(acc.PasswordReset.Token)) != 1 {
			log.Printf("reset-password: attempt to reset password for %s (account %s) is unauthorized: incorrect token",
				acc.Email, acc.ID)
			http.Error(w, "Incorrect reset token", http.StatusUnauthorized)
			return
		}

		if len(password) < MinPasswordLength {
			http.Error(w, fmt.Sprintf("Password must be at least %d characters", MinPasswordLength), http.StatusBadRequest)
			return
		}

		hashedPass, salt, err := createPassword(password)
		if err != nil {
			log.Printf("reset-password: could not create new password for %s: %v", acc.Email, err)
			http.Error(w, "Error resetting password", http.StatusInternalServerError) // don't leak details
			return
		}

		// set new password and clear reset authorization
		acc.Password = hashedPass
		acc.Salt = salt
		acc.PasswordReset = ResetToken{}

		err = saveAccount(acc)
		if err != nil {
			log.Printf("reset-password (step 2): error saving account: %v", err)
			http.Error(w, "Unable to reset password", http.StatusInternalServerError)
			return
		}

		log.Printf("reset-password: Successfully reset password for %s (account %s)\n", acc.Email, acc.ID)
	}

	w.WriteHeader(http.StatusOK)
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
	infos, _, _, _, err := getPluginInfos(r, true, false)
	if err != nil {
		log.Printf("list-plugins: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// send to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(infos)
}

// getPluginInfos returns the list of plugins, along with some values
// on the request: repo, version, and subfolder (in that order).
// If pullLatest is true, the latest will be pulled if the repo is
// already in the cache; otherwise the repo will stay unchanged.
// TODO: We don't need the subfolder.
func getPluginInfos(r *http.Request, pullLatest, requireSubfolder bool) ([]Plugin, string, string, string, error) {
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

	// get list of plugins
	infos, err := allPluginInfos(repo, version, subfolder, pullLatest)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("getting plugin list: %v", err)
	}

	// reject as error if any plugin name is not unique within this repo,
	// since it is otherwise impossible to distinguish one from another;
	// plugins don't have IDs until they're in the database
	if duplicate, dupName := anyDuplicatePluginName(infos); duplicate {
		return nil, "", "", "",
			fmt.Errorf("plugin name '%s' is not unique within repo %s", dupName, repo)
	}

	return infos, repo, version, subfolder, nil
}

// anyDuplicatePluginName checks for duplicate plugin names in infos.
// This will return true if a duplicate is found, along with the
// non-unique name. Otherwise false will be returned.
func anyDuplicatePluginName(infos []Plugin) (bool, string) {
	seen := make(map[string]struct{})
	for _, info := range infos {
		if _, ok := seen[info.Name]; ok {
			return true, info.Name
		}
		seen[info.Name] = struct{}{}
	}
	return false, ""
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
	acc.VerifiedDate = time.Now().UTC()

	err = saveAccount(acc)
	if err != nil {
		log.Printf("confirm-account: error updating database: %v", err)
		http.Error(w, "Unable to confirm account", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("confirm-account: Account confirmed: %s", acctID)
}

func registerAccount(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// validate input values
	name := strings.TrimSpace(r.Form.Get("name"))
	email := strings.TrimSpace(r.Form.Get("email")) // required
	password := r.Form.Get("password")              // required
	emailKey := strings.ToLower(email)
	if name == "" || email == "" {
		http.Error(w, "Name and email are required", http.StatusBadRequest)
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
		ID:                 acctID,
		Name:               name,
		Email:              email,
		Password:           hashedPass,
		Salt:               salt,
		APIKey:             apiKey,
		RegistrationDate:   time.Now().UTC(),
		EmailNotifyInfo:    true,
		EmailNotifySuccess: true,
		EmailNotifyWarn:    true,
		EmailNotifyError:   true,
	}

	err = saveAccount(acc)
	if err != nil {
		log.Printf("register-account: could not save account %s to database: %v", acctID, err)
		http.Error(w, "Error creating account", http.StatusInternalServerError)
		return
	}

	log.Printf("Registered new account: %#v\n", acc)

	val := url.Values{
		"email": []string{email},
		"code":  []string{acctID},
	}
	confirmPage := "https://caddyserver.com/account/verify"
	repl := strings.NewReplacer(
		"{name}", name,
		"{confirm_page}", confirmPage,
		"{confirm_link}", fmt.Sprintf("%s?%s", confirmPage, val.Encode()),
		"{account_id}", acctID)
	body := repl.Replace(confirmMsg)

	err = sendEmail(name, email, "Confirm your Caddy Developer Account", body)
	if err != nil {
		log.Printf("register-account: sending confirmation email to %s (account %s): %v", email, acctID, err)
		http.Error(w, "Error creating account", http.StatusInternalServerError)
		return
	}

	// TODO: delete account if not confirmed in 48 hours

	w.WriteHeader(http.StatusOK)
}

func sendEmail(toName, toEmail, subject, body string) error {
	from := mail.NewEmail(fromName, fromEmail)
	to := mail.NewEmail(toName, toEmail)
	content := mail.NewContent("text/plain", body)
	m := mail.NewV3MailInit(from, subject, to, content)

	request := sendgrid.GetRequest(os.Getenv("SENDGRID_API_KEY"), "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	request.Body = mail.GetRequestBody(m)
	_, err := sendgrid.API(request)
	return err
}

func registerPlugin(w http.ResponseWriter, r *http.Request) {
	var pl Plugin
	errMsg, statusCode, err := fillAndCheckPluginFromRequest(r, &pl)
	if err != nil {
		log.Printf("register-plugin: %v", err)
		http.Error(w, errMsg, statusCode)
		return
	}
	version := strings.TrimSpace(r.Form.Get("version"))
	if version == "" {
		version = "origin/master" // simply using "master" causes changes after initial pull to not be brought in
	}

	// save plugin to database
	err = savePlugin(pl)
	if err != nil {
		log.Printf("register-plugin: could not save plugin %s to database: %v", pl.ID, err)
		http.Error(w, "Error saving plugin", http.StatusInternalServerError)
		return
	}

	account := r.Context().Value(CtxKey("account")).(AccountInfo)

	log.Printf("Registered plugin %s (%s) (account %s: %s); initiating deploy",
		pl.ID, pl.Name, account.ID, account.Email)

	// initiate plugin deploy
	err = deployPlugin(pl.ID, pl.ImportPath, version, account)
	if err != nil {
		log.Printf("register-plugin: could not initiate deploy: %v", err)
		http.Error(w, "Error deploying plugin", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func editPlugin(w http.ResponseWriter, r *http.Request) {
	account := r.Context().Value(CtxKey("account")).(AccountInfo)

	pluginID := r.FormValue("plugin_id")
	if pluginID == "" {
		http.Error(w, "missing plugin ID", http.StatusBadRequest)
		return
	}

	pl, err := loadPlugin(pluginID)
	if err != nil {
		log.Printf("edit-plugin: loading plugin from DB: %v", err)
		http.Error(w, "error loading plugin", http.StatusBadRequest)
		return
	}

	if pl.OwnerAccountID != account.ID && !account.CaddyMaintainer { // Caddy maintainers should be able to edit plugins if necessary
		log.Printf("edit-plugin: account %s does not own plugin %s", account.ID, pl.ID)
		http.Error(w, "only plugin owners can edit their plugins", http.StatusForbidden)
		return
	}

	errMsg, statusCode, err := fillAndCheckPluginFromRequest(r, &pl)
	if err != nil {
		log.Printf("edit-plugin: %v", err)
		http.Error(w, errMsg, statusCode)
		return
	}

	// save plugin to database
	err = savePlugin(pl)
	if err != nil {
		log.Printf("edit-plugin: could not save plugin %s to database: %v", pl.ID, err)
		http.Error(w, "Error saving plugin", http.StatusInternalServerError)
		return
	}

	log.Printf("Updated plugin %s (%s) (account %s: %s)",
		pl.ID, pl.Name, account.ID, account.Email)

	w.WriteHeader(http.StatusOK)
}

func deleteNotification(w http.ResponseWriter, r *http.Request) {
	editNotification(w, r, "delete")
}

func ackNotification(w http.ResponseWriter, r *http.Request) {
	editNotification(w, r, "ack")
}

// editNotification will either delete or acknowledge the given notification(s)
// according to r. If action is "ack", the notification(s) will be acknowledged
// (marked as read). If "delete", it/they will be deleted. The notification ID
// can be "all" for, well, all of them.
func editNotification(w http.ResponseWriter, r *http.Request, action string) {
	account := r.Context().Value(CtxKey("account")).(AccountInfo)
	notifID := mux.Vars(r)["id"]
	if notifID == "" {
		http.Error(w, "missing notification ID", http.StatusBadRequest)
		return
	}

	notifs, err := loadNotifications(account.ID)
	if err != nil {
		log.Printf("notification change: could not load notifications for account %s: %v", account.ID, err)
		http.Error(w, "Error working with notification", http.StatusInternalServerError)
		return
	}

	var found bool
	for i := 0; i < len(notifs); i++ {
		if notifID == "all" || notifs[i].ID == notifID {
			if action == "ack" {
				notifs[i].Acknowledged = true
			} else if action == "delete" {
				notifs = append(notifs[:i], notifs[i+1:]...)
			}
			found = true
			if notifID != "all" {
				break
			}
		}
	}
	if !found {
		http.Error(w, "unknown notification", http.StatusBadRequest)
		return
	}

	err = setNotifications(account.ID, notifs)
	if err != nil {
		log.Printf("notification change: could not set notifications for account %s: %v", account.ID, err)
		http.Error(w, "Error working with notification", http.StatusInternalServerError)
		return
	}
}

func emailUnsubscribe(w http.ResponseWriter, r *http.Request) {
	acctID := r.FormValue("account")
	email := r.FormValue("email")
	levelStr := r.FormValue("level")

	level, err := strconv.Atoi(levelStr)
	if err != nil {
		log.Printf("unsubscribe (account %s): bad level '%s': %v", acctID, levelStr, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	account, err := loadAccount(acctID)
	if err != nil {
		log.Printf("unsubscribe (account %s): loading account: %v", acctID, err)
		http.Error(w, fmt.Sprintf("Unable to load account with ID: %s", acctID), http.StatusBadRequest)
		return
	}
	if strings.ToLower(account.Email) != strings.ToLower(email) {
		log.Printf("unsubscribe (account %s): email %s does not match that on account", account.ID, email)
		http.Error(w, "Bad unsubsribe request (wrong email)", http.StatusBadRequest)
		return
	}

	switch NotifLevel(level) {
	case NotifInfo:
		account.EmailNotifyInfo = false
	case NotifSuccess:
		account.EmailNotifySuccess = false
	case NotifWarn:
		account.EmailNotifyWarn = false
	case NotifError:
		account.EmailNotifyError = false
	}

	err = saveAccount(account)
	if err != nil {
		log.Printf("unsubscribe (account %s): unable to save account: %v", account.ID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "The account %s has been unsubscribed from %s notification emails.",
		account.Email, NotifLevelText(NotifLevel(level)))
}

func toggleEmailNotifs(w http.ResponseWriter, r *http.Request) {
	account := r.Context().Value(CtxKey("account")).(AccountInfo)
	levelStr := r.FormValue("level")
	enabled := r.FormValue("enabled")

	level, err := strconv.Atoi(levelStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch NotifLevel(level) {
	case NotifInfo:
		account.EmailNotifyInfo = enabled == "true"
	case NotifSuccess:
		account.EmailNotifySuccess = enabled == "true"
	case NotifWarn:
		account.EmailNotifyWarn = enabled == "true"
	case NotifError:
		account.EmailNotifyError = enabled == "true"
	}

	err = saveAccount(account)
	if err != nil {
		log.Printf("toggling email notifications: %v", err)
		http.Error(w, "Unable to save changes to account", http.StatusInternalServerError)
		return
	}
}

// fillAndCheckPluginFromRequest unloads data about a plugin into pl.
// pl must not be nil. If it is a plugin to be newly created, pass in
// a pointer to an empty plugin (without an ID). It will then be created
// and certain form fields are required (such as name and type), and
// certain checks are performed. If pl has an ID already, its fields
// will be set to whatever fields are set in the request body.
// Any examples on the request will replace all existing examples.
//
// If an error is returned, an error message (first value) and recommended
// status code (second value) will also be returned.
func fillAndCheckPluginFromRequest(r *http.Request, pl *Plugin) (string, int, error) {
	now := time.Now().UTC()

	infos, repo, _, _, err := getPluginInfos(r, true, false)
	if err != nil {
		return err.Error(), http.StatusBadRequest, err
	}

	name := strings.TrimSpace(strings.ToLower(r.Form.Get("plugin_name")))
	pluginType := r.Form.Get("plugin_type")
	pkg := strings.TrimSpace(r.Form.Get("import_path"))
	description := strings.TrimSpace(r.Form.Get("description"))
	website := strings.TrimSpace(r.Form.Get("website"))
	support := strings.TrimSpace(r.Form.Get("support_link"))
	docs := strings.TrimSpace(r.Form.Get("docs_link"))

	// if registering a new plugin...
	if pl.ID == "" {
		// we need certain information
		if name == "" || pluginType == "" || pkg == "" || description == "" ||
			website == "" || support == "" || docs == "" {
			return "missing required field(s)", http.StatusBadRequest,
				fmt.Errorf("edit-plugin: missing required field(s) from: %+v", r.Form)
		}

		// ensure name is unique
		if !isUnique("index:namesToPlugins", name) {
			return "a plugin named '" + name + "' is already published", http.StatusConflict,
				fmt.Errorf("a plugin named %s is already published", name)
		}

		// make sure the plugin name is valid
		if matched, err := regexp.MatchString(`^[\w\d\.]+$`, name); !matched || err != nil {
			return "plugin name is invalid", http.StatusBadRequest,
				fmt.Errorf("plugin name '%s' is invalid", name)
		}
	}

	// TODO: ensure import path is unique in DB? (build worker can't distinguish
	// between different plugins in the same package; it just imports the
	// whole package... multiple plugins may be in a package but only one
	// can be published or 'plugged in' by the user, the rest would just
	// come with it, which is fine) - Is this really needed?

	// ensure plugin is in the repository
	var found bool
	if name == "" || pluginType == "" {
		// if we're registering a new plugin, then we won't hit
		// this condition; otherwise, just get the values that
		// we're looking for in a moment from the existing plugin
		name = pl.Name
		pluginType = pl.Type.ID
	}
	for _, info := range infos {
		if info.Name == name && info.Type.ID == pluginType {
			found = true
			if pl.ID == "" {
				// if plugin is new, begin to fill in the plugin's information
				*pl = info
				pl.ID, err = uniqueID("plugins")
				if err != nil {
					return "No unique IDs available; try again", http.StatusInternalServerError,
						fmt.Errorf("no unique IDs available as plugin ID (for %s)", repo)
				}
				pl.Published = now
				pl.OwnerAccountID = r.Context().Value(CtxKey("account")).(AccountInfo).ID
			}
		}
	}
	if !found {
		return "plugin name not found in repo", http.StatusBadRequest,
			fmt.Errorf("no plugin of type '%s' named '%s' in '%s'", pluginType, name, repo)
	}

	// fill in the rest of the information
	if _, ok := r.Form["import_path"]; ok {
		pl.ImportPath = pkg
	}
	if _, ok := r.Form["clone_url"]; ok {
		pl.SourceRepo = repo
	}
	// if _, ok := r.Form["subfolder"]; ok { // TODO: needed?
	// 	pl.Subfolder = subfolder
	// }
	if _, ok := r.Form["description"]; ok {
		pl.Description = description
	}
	if _, ok := r.Form["website"]; ok {
		pl.Website = website
	}
	if _, ok := r.Form["support_link"]; ok {
		pl.Support = support
	}
	if _, ok := r.Form["docs_link"]; ok {
		pl.Docs = docs
	}
	pl.Updated = now

	// check example fields
	if len(r.Form["example_title"]) != len(r.Form["example_code"]) ||
		len(r.Form["example_code"]) != len(r.Form["example_explanation"]) {
		return "example data is mismatched; probably a website bug", http.StatusBadRequest,
			fmt.Errorf("example fields don't match up: %+v %+v %+v",
				r.Form["example_title"], r.Form["example_code"], r.Form["example_explanation"])
	}

	// if any examples have been submitted, replace all existing examples
	if len(r.Form["example_code"]) > 0 {
		pl.Examples = []Example{}
	}
	for i := range r.Form["example_code"] {
		ex := Example{
			Title:       r.Form["example_title"][i],
			Code:        r.Form["example_code"][i],
			Explanation: r.Form["example_explanation"][i],
		}
		if ex.Code == "" {
			continue // skip examples without actual content
		}
		pl.Examples = append(pl.Examples, ex)
	}

	return "", http.StatusOK, nil
}

const fromName = "Caddy Web Server"
const fromEmail = "no-reply@caddyserver.com"

const confirmMsg = `Hi {name},

You (or somebody pretending to be you) created a new account at caddyserver.com with this email address. 

Before you can use your account, please click this link to activate it:

{confirm_link}

Or go to {confirm_page} and enter your account ID manually: {account_id}

This link expires in 48 hours. If you do not wish to keep the account, simply ignore this message and it will be deleted.

Thank you!

-The Caddy Maintainers`

const resetMsg = `Hi {name},

You (or somebody pretending to be you) requested a password reset at caddyserver.com for the account with this email address.

To reset your password, click this link:

{reset_link}

Or go to {reset_page} and enter this token manually: {token}

This token expires in 24 hours.

Farewell!

-The Caddy Maintainers`
