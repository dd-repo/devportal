package devportal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	mathrand "math/rand"
	"net/http"
	"time"

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
	var err error
	db, err = openDB(dbFile)
	if err != nil {
		return err
	}
	defer db.Close()

	addRoute := func(method, path string, h http.HandlerFunc) {
		router.Handle(path, handlers.MethodHandler{method: h})
	}
	addRoute("GET", "/api/download-page", populateDownloadPage)
	addRoute("POST", "/api/login", login)
	addRoute("POST", "/api/logout", logout)
	addRoute("POST", "/api/register-account", registerAccount)
	addRoute("POST", "/api/confirm-account", confirmAccount)
	addRoute("POST", "/api/repo-plugins", authHandler(listPlugins, unauthAPI))
	addRoute("POST", "/api/register-plugin", authHandler(registerPlugin, unauthAPI))
	addRoute("POST", "/api/deploy-caddy", authHandler(deployCaddyHandler, unauthAPI))
	addRoute("POST", "/api/deploy-plugin", authHandler(deployPluginHandler, unauthAPI))
	addRoute("POST", "/webhook/github/{accountID}", githubWebhook)
	addRoute("GET", "/account/login.html", loginPage)
	addRoute("GET", "/account/dashboard.html", authHandler(templatedPage, unauthPage))
	addRoute("GET", "/account/register-plugin.html", authHandler(templatedPage, unauthPage))
	addRoute("GET", "/download/{os}/{arch}", downloadHandler)
	addRoute("GET", "/download/{os}/{arch}/signature", signatureHandler)

	// protect against large requests
	maxBytesHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.RawQuery) > MaxQueryStringLength {
			http.Error(w, "query string exceeded length limit", http.StatusRequestURITooLong)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		router.ServeHTTP(w, r)
	})

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
	db     *bolt.DB
	router = mux.NewRouter()
)
