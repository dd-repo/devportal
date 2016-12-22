package devportal

import (
	"bytes"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
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

// OwnedPlugins gets a list of plugins owned by the current user.
func (c *TemplateContext) OwnedPlugins() []Plugin {
	// TODO...
	return nil
}

var cookies = sessions.NewCookieStore(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
)

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

// CtxKey is string used for context.Context values.
type CtxKey string
