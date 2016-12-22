package devportal

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
)

// unauthPage handles unauthorized requests for browser pages.
// For use with authHandler.
func unauthPage(w http.ResponseWriter, r *http.Request, err error) {
	log.Println(err)
	v := url.Values{}
	v.Set("redir", strings.TrimSuffix(r.URL.RequestURI(), ".html"))
	http.Redirect(w, r, "/account/login?"+v.Encode(), http.StatusSeeOther)
}

// unauthAPI handles unauthorized requests for API endpoints.
// For use with authHandler.
func unauthAPI(w http.ResponseWriter, r *http.Request, err error) {
	log.Println(err)
	http.Error(w, "unacceptable credentials", http.StatusUnauthorized)
}

// authHandler wraps h by ensuring that the client is logged in or at
// least authenticated with an API key. If the client cannot be verified,
// then unauth is executed to handle the request. Otherwise, the logged
// in user is added to the request context as "account".
func authHandler(h http.HandlerFunc, unauth func(http.ResponseWriter, *http.Request, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// first check cookies...
		acc, err1 := getLoggedInAccount(r)
		if err1 != nil {
			// ...then check API credentials
			var err2 error
			acc, err2 = getAccountFromAPICredentials(r)
			if err2 != nil {
				unauth(w, r, fmt.Errorf("%v and %v", err1, err2))
				return
			}
		}

		// set the account info on the request
		ctx := context.WithValue(r.Context(), CtxKey("account"), acc)

		h.ServeHTTP(w, r.WithContext(ctx))
	}
}

// githubWebhook processes a webhook request from GitHub.
func githubWebhook(w http.ResponseWriter, r *http.Request) {
	status, err := authenticateGitHubWebhook(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	// TODO: Ensure event is a push (or a release?)
	// and if a push, to ensure correct branch or something.
	// See: https://github.com/phayes/hookserve/blob/master/hookserve/hookserve.go

	// TODO: implement.
}

func authenticateGitHubWebhook(r *http.Request) (int, error) {
	// ensure request has necessary parameters
	if r.Method != "POST" {
		return http.StatusMethodNotAllowed, fmt.Errorf("method '%s' not allowed", r.Method)
	}
	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		return http.StatusBadRequest, fmt.Errorf("missing X-GitHub-Event header")
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return http.StatusBadRequest, err
	}
	sig := r.Header.Get("X-Hub-Signature")
	if sig == "" {
		return http.StatusUnauthorized, fmt.Errorf("missing X-Hub-Signature header required for HMAC verification")
	}

	// load account and verify API key
	accountID := mux.Vars(r)["accountID"]
	acc, err := loadAccount(accountID)
	if err != nil {
		return http.StatusBadRequest, err
	}
	mac := hmac.New(sha1.New, acc.APIKey)
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expectedSig := "sha1=" + hex.EncodeToString(expectedMAC)
	if !hmac.Equal([]byte(expectedSig), []byte(sig)) {
		return http.StatusUnauthorized, fmt.Errorf("HMAC verification failed")
	}

	return http.StatusOK, nil
}

// getAccountFromAPICredentials gets the user account information
// based on credentials in the request. An error is returned
// if credentials are bad or anything else goes wrong. The
// returned error may be logged but should not be revealed.
func getAccountFromAPICredentials(r *http.Request) (AccountInfo, error) {
	acctID, apiKey, ok := r.BasicAuth()
	if !ok {
		return AccountInfo{}, fmt.Errorf("checking API credentials: no basic auth")
	}
	acc, err := loadAccount(acctID)
	if err != nil {
		return acc, fmt.Errorf("checking API credentials: could not load account with ID '%s': %v", acctID, err)
	}
	if acc.VerifiedDate.IsZero() {
		return acc, fmt.Errorf("checking API credentials: account %s (%s) is not confirmed", acc.ID, acc.Email)
	}
	err = assertAPIKeysMatch(apiKey, acc.APIKey)
	if err != nil {
		return acc, fmt.Errorf("checking API credentials: incorrect credentials for account %s (%s): %v", acc.ID, acc.Email, err)
	}
	return acc, nil
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
