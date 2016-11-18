package devportal

import (
	"crypto/rand"
	"crypto/subtle"
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
	addRoute("POST", "/api/login", login)
	addRoute("POST", "/api/logout", logout)
	addRoute("POST", "/api/register-account", registerAccount)
	addRoute("POST", "/api/register-plugin", registerPlugin)
	addRoute("POST", "/api/confirm-account", confirmAccount)
	addRoute("POST", "/api/repo-plugins", authHandler(getRepoPlugins, unauthAPI))
	addRoute("GET", "/account/login.html", loginPage)
	addRoute("GET", "/account/dashboard.html", authHandler(accountPage, unauthPage))

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
	salt := make([]byte, PasswordSaltBytes)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, nil, err
	}
	hash, err := scrypt.Key([]byte(plaintext), salt, 1<<14, 8, 1, PasswordHashBytes)
	if err != nil {
		return nil, nil, err
	}
	return hash, salt, nil
}

// assertPasswordsMatch asserts that the plaintext password matches
// the hashed password with the provided salt. A nil error indicates
// a match.
func assertPasswordsMatch(plaintext string, hashed, salt []byte) error {
	hash, err := scrypt.Key([]byte(plaintext), salt, 1<<14, 8, 1, PasswordHashBytes)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash, hashed) == 1 {
		return nil
	}
	return errors.New("incorrect password")
}

// randString returns a string of n random characters.
// It is not even remotely secure or a proper distribution.
// But it's good enough for some things.
func randString(n int) string {
	if n <= 0 {
		return ""
	}
	dict := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]byte, n)
	for i := range b {
		b[i] = dict[mathrand.Int63()%int64(len(dict))]
	}
	return string(b)
}

const (
	PasswordSaltBytes = 32
	PasswordHashBytes = 64

	MinPasswordLength = 12

	MaxBodyBytes         = 1 * 1024 * 1024
	MaxQueryStringLength = 128 * 1024
)

var (
	db     *bolt.DB
	router = mux.NewRouter()
)
