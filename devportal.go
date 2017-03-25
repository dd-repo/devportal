package devportal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"golang.org/x/crypto/scrypt"

	"github.com/boltdb/bolt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func init() {
	mathrand.Seed(time.Now().UnixNano())
}

// Serve begins the developer portal listening.
func Serve(addr, dbFile string) error {
	// set up log before anything bad happens
	switch Log {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	case "":
		log.SetOutput(ioutil.Discard)
	default:
		log.SetOutput(&lumberjack.Logger{
			Filename:   Log,
			MaxSize:    100,
			MaxAge:     120,
			MaxBackups: 5,
		})
	}

	var err error
	db, err = openDB(dbFile)
	if err != nil {
		return err
	}
	defer db.Close()

	// delete really old notifications
	go func() {
		olderThan := (24 * time.Hour * 30) * 12 // 1 year
		for {
			err := db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("notifications"))
				c := b.Cursor()
				for key, val := c.First(); key != nil; key, val = c.Next() {
					if val == nil {
						continue
					}
					var notifs []Notification
					err := gobDecode(val, &notifs)
					if err != nil {
						return err
					}
					var changed bool
					for i := 0; i < len(notifs); i++ {
						if time.Since(notifs[i].Timestamp) > olderThan {
							changed = true
							notifs = append(notifs[:i], notifs[i+1:]...)
						}
					}
					if changed {
						enc, err := gobEncode(notifs)
						if err != nil {
							return fmt.Errorf("error encoding for database: %v", err)
						}
						err = b.Put(key, enc)
						if err != nil {
							return err
						}
					}
				}
				return nil
			})
			if err != nil {
				log.Printf("[ERROR] Removing old notifications: %v", err)
			}
			time.Sleep(6 * time.Hour)
		}
	}()

	addRoute := func(methods, path string, h http.HandlerFunc) {
		methodHandler := make(handlers.MethodHandler)
		for _, method := range strings.Split(methods, ",") {
			methodHandler[method] = h
		}
		router.Handle(path, methodHandler)
	}

	addRoute("GET", "/docs.html", docsHandler)
	addRoute("GET", "/docs/{pluginName}", docsHandler) // handler will check if {pluginName} is actually a static file
	addRoute("GET", "/api/download-page", populateDownloadPage)
	addRoute("POST", "/api/login", login)
	addRoute("POST", "/api/logout", logout)
	addRoute("POST", "/api/register-account", registerAccount)
	addRoute("POST", "/api/confirm-account", confirmAccount)
	addRoute("POST", "/api/reset-password", resetPassword)
	addRoute("POST", "/api/toggle-email", authHandler(toggleEmailNotifs, unauthAPI))
	addRoute("POST", "/api/repo-plugins", authHandler(listPlugins, unauthAPI))
	addRoute("POST", "/api/register-plugin", authHandler(registerPlugin, unauthAPI))
	addRoute("POST", "/api/edit-plugin", authHandler(editPlugin, unauthAPI))
	addRoute("POST", "/api/deploy-caddy", authHandler(deployCaddyHandler, unauthAPI))
	addRoute("POST", "/api/deploy-plugin", authHandler(deployPluginHandler, unauthAPI))
	addRoute("POST", "/webhook/github/{accountID}", githubWebhook)
	addRoute("GET", "/account/login.html", loggedInRedir(staticPage))
	addRoute("GET", "/account/register.html", loggedInRedir(staticPage))
	addRoute("GET", "/account/verify.html", loggedInRedir(staticPage))
	addRoute("GET", "/account/reset-password.html", loggedInRedir(staticPage))
	addRoute("GET", "/account/dashboard.html", authHandler(templatedPage, unauthPage))
	addRoute("GET", "/account/register-plugin.html", authHandler(templatedPage, unauthPage))
	addRoute("GET", "/account/notifications.html", authHandler(templatedPage, unauthPage))
	addRoute("GET", "/account/plugin/{id}", accountTplPluginOwner("/account/plugin-details.html"))
	addRoute("GET", "/account/plugin/{id}/edit", accountTplPluginOwner("/account/plugin-edit.html"))
	addRoute("GET", "/account/plugin/{id}/deploy", accountTplPluginOwner("/account/plugin-deploy.html"))
	addRoute("GET", "/account/unsubscribe", emailUnsubscribe)
	addRoute("POST", "/account/notification/{id}/ack", authHandler(ackNotification, unauthAPI))
	addRoute("POST", "/account/notification/{id}/delete", authHandler(deleteNotification, unauthAPI))
	addRoute("GET,HEAD", "/download/{os}/{arch}", downloadHandler)
	addRoute("GET,HEAD", "/download/{os}/{arch}/signature", signatureHandler)

	// protect against large requests
	maxBytesHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.RawQuery) > MaxQueryStringLength {
			http.Error(w, "query string exceeded length limit", http.StatusRequestURITooLong)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		router.ServeHTTP(w, r)
	})

	err = cachedBuildsMaintenance()
	if err != nil {
		return fmt.Errorf("maintaining build cache: %v", err)
	}

	// TODO: A middleware to log requests and give them an ID, I guess

	return http.ListenAndServe(addr, maxBytesHandler)
}

// createPassword salts and hashes the plaintext password, returning
// the hashed password and its salt if there was no error.
func createPassword(plaintext string) ([]byte, []byte, error) {
	salt := make([]byte, passwordSaltBytes)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, nil, err
	}
	hash, err := hashPassword(plaintext, salt)
	if err != nil {
		return nil, nil, err
	}
	return hash, salt, nil
}

// assertAPIKeysMatch carefully asserts that encodedKey (encoded)
// matches rawKey (raw bytes). A nil error indicates a match.
func assertAPIKeysMatch(encodedKey string, rawKey []byte) error {
	rawKeyEncoded := make([]byte, hex.EncodedLen(len(rawKey)))
	hex.Encode(rawKeyEncoded, rawKey)
	if subtle.ConstantTimeCompare([]byte(encodedKey), rawKeyEncoded) == 1 {
		return nil
	}
	return errors.New("incorrect API key")
}

// assertPasswordsMatch asserts that the plaintext password matches
// the hashed password with the provided salt. A nil error indicates
// a match.
func assertPasswordsMatch(plaintext string, hashed, salt []byte) error {
	hash, err := hashPassword(plaintext, salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash, hashed) == 1 {
		return nil
	}
	return errors.New("incorrect password")
}

// hashPassword hashes plaintext with salt using a secure, slow
// hashing algorithm.
func hashPassword(plaintext string, salt []byte) ([]byte, error) {
	defer debug.FreeOSMemory() // wow. https://groups.google.com/forum/#!topic/golang-nuts/I9R9MKUS9bo
	return scrypt.Key([]byte(plaintext), salt, 1<<14, 8, 1, passwordHashBytes)
}

// randString returns a string of n random characters.
// It is not even remotely secure or a proper distribution.
// But it's good enough for some things. It excludes certain
// confusing characters like I, l, 1, 0, O, etc.
func randString(n int) string {
	if n <= 0 {
		return ""
	}
	dict := []byte("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789")
	b := make([]byte, n)
	for i := range b {
		b[i] = dict[mathrand.Int63()%int64(len(dict))]
	}
	return string(b)
}

const (
	// MinPasswordLength is the minimum length of a password.
	MinPasswordLength = 12

	// MaxBodyBytes is the maximum number of bytes a
	// request body may have.
	MaxBodyBytes = 1 * 1024 * 1024

	// MaxQueryStringLength is the maximum allowed size
	// of a query string.
	MaxQueryStringLength = 128 * 1024

	passwordSaltBytes = 32
	passwordHashBytes = 64
)

var (
	db       *bolt.DB
	router   = mux.NewRouter()
	SiteRoot string
	Log      = "devportal.log"
)
