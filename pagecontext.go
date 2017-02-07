package devportal

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"text/template"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/russross/blackfriday"
)

// TemplateContext is a struct that is used to render templates.
type TemplateContext struct {
	root    string
	Req     *http.Request
	Account AccountInfo
	Args    []interface{}
}

// Include includes another file.
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

// Markdown returns the HTML contents of the markdown contained in filename
// (relative to the site root).
func (c *TemplateContext) Markdown(body string) (string, error) {
	renderer := blackfriday.HtmlRenderer(0, "", "")
	var extns int
	extns |= blackfriday.EXTENSION_TABLES
	extns |= blackfriday.EXTENSION_FENCED_CODE
	extns |= blackfriday.EXTENSION_STRIKETHROUGH
	extns |= blackfriday.EXTENSION_DEFINITION_LISTS
	markdown := blackfriday.Markdown([]byte(body), renderer, extns)

	return string(markdown), nil
}

// OwnedPlugins gets a list of plugins owned by the current user.
func (c *TemplateContext) OwnedPlugins() []Plugin {
	acct := c.Req.Context().Value(CtxKey("account")).(AccountInfo)
	plugins, err := loadAllPlugins(acct.ID)
	if err != nil {
		log.Printf("Error loading plugins owned by %s: %v", acct.ID, err)
		return nil
	}
	return plugins
}

func (c *TemplateContext) LoadPlugin(id string) (Plugin, error) {
	return loadPlugin(id)
}

func (c *TemplateContext) Notifications() ([]Notification, error) {
	return loadNotifications(c.Account.ID)
}

func (c *TemplateContext) PathVar(name string) string {
	return mux.Vars(c.Req)[name]
}

func (c *TemplateContext) Context(key string) interface{} {
	return c.Req.Context().Value(CtxKey(key))
}

func (c *TemplateContext) When(then time.Time) string {
	return humanize.Time(then)
}

var cookies = sessions.NewCookieStore(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
)

func renderTemplatedPage(w http.ResponseWriter, r *http.Request, templatePage string) {
	ctx := &TemplateContext{
		root:    siteRoot,
		Req:     r,
		Account: r.Context().Value(CtxKey("account")).(AccountInfo),
	}

	tmpl, err := template.ParseFiles(filepath.Join(siteRoot, templatePage))
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

// CtxKey is string used for context.Context values.
type CtxKey string
