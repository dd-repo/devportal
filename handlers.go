package devportal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
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
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	repo := strings.TrimSpace(r.Form.Get("clone_url"))
	pkg := strings.TrimSpace(r.Form.Get("import_path"))
	version := strings.TrimSpace(r.Form.Get("version"))
	subfolder := strings.TrimSpace(r.Form.Get("subfolder"))
	if repo == "" || pkg == "" {
		http.Error(w, "Missing required field(s)", http.StatusBadRequest)
		return
	}

	// assume root of repository if no subfolder given
	if subfolder == "" {
		subfolder = "."
	}

	infos, err := allPluginInfos(repo, version, subfolder, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Println(json.NewEncoder(w).Encode(infos))
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
	acctID := randString(16)
	for i, maxTries := 0, 50; !isUnique("accounts", acctID) && i < maxTries; i++ {
		if i == maxTries-1 {
			log.Printf("register-account: No unique IDs available as account ID (for %s)", email)
			http.Error(w, "No unique IDs available; try again", http.StatusInternalServerError)
			return
		}
		acctID = randString(16)
	}

	// salt and hash
	hashedPass, salt, err := createPassword(password)
	if err != nil {
		log.Printf("register-account: could not create password for %s: %v", email, err)
		// don't leak details
		http.Error(w, "Error creating account", http.StatusInternalServerError)
		return
	}

	acc := AccountInfo{
		ID:               acctID,
		Email:            email,
		Password:         hashedPass,
		Salt:             salt,
		RegistrationDate: time.Now(),
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

// TODO: This handler needs some work
func registerPlugin(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Get owner/author account information

	var input PluginInfo
	input.Name = r.Form.Get("plugin_name")             // required -- TODO: Infer from code...
	input.ImportPath = r.Form.Get("import_path")       // required
	input.SourceRepo = r.Form.Get("source_repo")       // required, if different from import_path
	input.ReleaseBranch = r.Form.Get("release_branch") // default=master
	input.DocsRepo = r.Form.Get("docs_repo")           // required, if different from source_repo
	input.DocsBranch = r.Form.Get("docs_branch")       // default=caddydocs (if docs_repo is blank)
	input.DocsManifest = r.Form.Get("docs_manifest")   // default="manifest.yaml"

	fmt.Printf("%#v\n", input)

	// TODO: verify input (no duplicate names, import paths, etc...) <-- just what would stop them from submitting the form

	// TODO: Might actually gob-encode this...
	enc, err := json.Marshal(input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// save input and add to review queue
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins"))
		return b.Put([]byte(input.Name), enc)
	})

	fmt.Println("Saved plugin")

	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins"))
		v := b.Get([]byte(input.Name))
		fmt.Printf("%+s\n", v)
		return nil
	})

	// TODO: begin running tests or something
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	// if user is already logged in, redirect them to dashboard
	if _, err := getLoggedInAccount(r); err == nil {
		http.Redirect(w, r, "/account/dashboard", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, "/Users/matt/Sites/newcaddy/account/login.html")
}

func templatedPage(w http.ResponseWriter, r *http.Request) {
	root := "/Users/matt/Sites/newcaddy"
	ctx := &TemplateContext{
		root:    root,
		Req:     r,
		Account: r.Context().Value(CtxKey("account")).(AccountInfo),
	}

	tmpl, err := template.ParseFiles(filepath.Join(root, r.URL.Path))
	if err != nil {
		log.Printf("template parsing: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, ctx)
	if err != nil {
		log.Printf("template execution: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = buf.WriteTo(w)
	if err != nil {
		log.Printf("writing template buffer to wire: %v", err)
		return
	}
}

// unauthPage handles unauthorized requests for browser pages.
// For use with AuthHandler.
func unauthPage(w http.ResponseWriter, r *http.Request, err error) {
	log.Println(err)
	v := url.Values{}
	v.Set("redir", strings.TrimSuffix(r.URL.RequestURI(), ".html"))
	http.Redirect(w, r, "/account/login?"+v.Encode(), http.StatusSeeOther)
}

// unauthAPI handles unauthorized requests for API endpoints.
// For use with AuthHandler.
func unauthAPI(w http.ResponseWriter, r *http.Request, err error) {
	log.Println(err)
	http.Error(w, "not logged in", http.StatusUnauthorized)
}

// authHandler wraps h by ensuring that the client is logged in. If the
// client cannot be verified to be logged in, then unauth is executed
// to handle the request. Otherwise, the logged in user is added to the
// request context as "account".
func authHandler(h http.HandlerFunc, unauth func(http.ResponseWriter, *http.Request, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		acc, err := getLoggedInAccount(r)
		if err != nil {
			unauth(w, r, err)
			return
		}

		// set the account info on the request
		ctx := context.WithValue(r.Context(), CtxKey("account"), acc)

		h.ServeHTTP(w, r.WithContext(ctx))
	}
}

// getLoggedInAccount gets the currently-logged-in user from r,
// if the user is logged in. If the user is not logged in, that
// counts as an error.
func getLoggedInAccount(r *http.Request) (AccountInfo, error) {
	sess, err := cookies.Get(r, "user")
	if err != nil {
		return AccountInfo{}, fmt.Errorf("checking login: getting user session from cookie: %v", err)
	}
	var acctID string
	idVal, ok := sess.Values["id"]
	if !ok {
		return AccountInfo{}, fmt.Errorf("checking login: no id value in session")
	}
	acctID, ok = idVal.(string)
	if !ok {
		return AccountInfo{}, fmt.Errorf("checking login: could not convert id value to string")
	}
	acc, err := loadAccount(acctID)
	if err != nil {
		return acc, fmt.Errorf("checking login: could not load account with ID '%s': %v", acctID, err)
	}
	return acc, nil
}

type TemplateContext struct {
	root    string
	Req     *http.Request
	Account AccountInfo
	Args    []interface{}
}

func (c *TemplateContext) Include(filename string, args ...interface{}) (string, error) {
	file, err := os.Open(filepath.Join(c.root, filename))
	if err != nil {
		return "", err
	}
	defer file.Close()

	body, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	tpl, err := template.New(filename).Parse(string(body))
	if err != nil {
		return "", err
	}

	c.Args = args

	var buf bytes.Buffer
	err = tpl.Execute(&buf, c)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (c *TemplateContext) OwnedPlugins() []PluginInfo {
	// TODO...
	return nil
}

var cookies = sessions.NewCookieStore(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
)

// CtxKey is string used for context.Context values.
type CtxKey string
