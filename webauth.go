// Package webauth is an experimental package to add Google OAuth user flow to a web
// server.
package webauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/NYTimes/gizmo/auth"
	"github.com/NYTimes/gizmo/auth/gcp"
	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	kmsv1 "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type (
	// Authenticator leans on Google's OAuth user flow to capture a Google Identity JWS
	// and use it in a local, short lived HTTP cookie. The `Middleware` function manages
	// login redirects, OAuth callbacks, dropping the HTTP cookie and adding the JWS
	// claims information to the request context. User information and the JWS token can
	// be retrieved from the context via GetInfo function.
	// The user state in the login flow is encrypted using Google KMS. Ensure the service
	// account being used has permissions to encrypt and decrypt.
	Authenticator struct {
		cfg          Config
		secureCookie bool
		cookieDomain string
		callbackPath string

		keyName  string
		keys     *kms.KeyManagementClient
		verifier *auth.Verifier
		log      log.Logger
	}

	// Config encapsulates the needs of the Authenticator.
	Config struct {
		// CookieName will be used for the local HTTP cookie name.
		CookieName string

		// KMSKeyName is used by a Google KMS client for encrypting and decrypting state
		// tokens within the oauth exchange.
		KMSKeyName string
		// UnsafeState can be used to skip the encryption of the "state" token
		// within the auth flow.
		UnsafeState bool

		// AuthConfig is used by Authenticator.Middleware and callback to enable the
		// Google OAuth flow.
		AuthConfig *oauth2.Config

		// how long login is valid for (cookie setting).  If not set, defaults to 1 day.
		LoginValidMinutes int

		// HeaderExceptions can optionally be included. Any requests that include any of
		// the headers included will skip all Authenticator.Middleware checks and no
		// claims information will be added to the context.
		// This can be useful for unspoofable headers like Google App Engine's
		// "X-AppEngine-*" headers for Google Task Queues.
		HeaderExceptions []string

		// Allow any custom exceptions based on the request.  For example, looking for
		// specific URIs.  Return true if should be allowed.  If false is returned,
		// normal cookie-based authentication happens.
		CustomExceptionsFunc func(context.Context, *http.Request) bool

		// IDConfig will be used to verify the Google Identity JWS when it is inbound
		// in the HTTP cookie.
		IDConfig gcp.IdentityConfig

		// IDVerifyFunc allows developers to add their own verification on the user
		// claims. For example, one could enable access for anyone with an email domain
		// of "@example.com".
		IDVerifyFunc func(context.Context, gcp.IdentityClaimSet) bool

		// Redirect path on auth failure.  This path is always allowed to avoid
		// redirect loops.  However - make sure any resources this path uses
		// (e.g., css/js) are either in-line or allowed via CustomExceptionsFunc
		AuthFailurePath string

		// Logger will be used to log any errors encountered during the auth flow.
		Logger log.Logger
	}
)

// New will instantiate a new Authenticator.
func New(ctx context.Context, cfg Config) (Authenticator, error) {
	ks, err := gcp.NewIdentityPublicKeySource(ctx, cfg.IDConfig)
	if err != nil {
		return Authenticator{}, errors.Wrap(err, "unable to init key source")
	}
	u, err := url.Parse(cfg.AuthConfig.RedirectURL)
	if err != nil {
		return Authenticator{}, errors.Wrap(err, "unable to pasrse redirect URL")
	}
	var keys *kms.KeyManagementClient
	if !cfg.UnsafeState {
		keys, err = kms.NewKeyManagementClient(ctx)
		if err != nil {
			return Authenticator{}, errors.Wrap(err, "unable to init KMS client")
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.NewNopLogger()
	}
	return Authenticator{
		cfg:          cfg,
		keys:         keys,
		cookieDomain: strings.Split(u.Host, ":")[0],
		secureCookie: u.Scheme == "https",
		callbackPath: u.Path,
		verifier: auth.NewVerifier(ks, gcp.IdentityClaimsDecoderFunc,
			gcp.IdentityVerifyFunc(cfg.IDVerifyFunc)),
	}, nil
}

// Middleware will handle login redirects, OAuth callbacks, header exceptions, verifying
// inbound Google ID JWS' within HTTP cookies and, if the user passes all checks, it will
// add the user claims to the inbound request context.
func (c Authenticator) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == c.callbackPath {
			c.callbackHandler(w, r)
			return
		}

		// always allow auth failure path
		if c.cfg.AuthFailurePath != "" && r.RequestURI == c.cfg.AuthFailurePath {
			h.ServeHTTP(w, r)
			return
		}

		// if one of the 'exception' headers exists, let the request pass through
		// this is nice for unspoofable headers like 'X-Appengine-*'.
		for _, hdr := range c.cfg.HeaderExceptions {
			if r.Header.Get(hdr) != "" {
				h.ServeHTTP(w, r)
				return
			}
		}

		// if this is a custom exception, let through
		if c.cfg.CustomExceptionsFunc != nil && c.cfg.CustomExceptionsFunc(r.Context(), r) {
			h.ServeHTTP(w, r)
			return
		}

		// ***all other endpoints must have a cookie***

		ck, err := r.Cookie(c.cfg.CookieName)
		if err != nil || ck == nil {
			c.redirect(w, r)
			return
		}

		if okay := c.verify(w, r, ck.Value); !okay {
			return
		}

		claims, err := decodeClaims(ck.Value)
		if err != nil {
			c.redirect(w, r)
			return
		}

		// add the user claims to the context and call the handlers below
		r = r.WithContext(context.WithValue(r.Context(), claimsKey, claims))
		h.ServeHTTP(w, r)
	})
}

// Verify id using verify function.  Redirect to AuthFailurePath if provided, otherwise
// respond with Status Forbidden.  Return true if ok to proceed.
func (c Authenticator) verify(w http.ResponseWriter, r *http.Request, id string) bool {
	verified, err := c.verifier.Verify(r.Context(), id)
	if err != nil {
		c.redirect(w, r)
		return false
	}
	// we know who you are, but for some reason you dont have access.
	if !verified {
		// if auth failure redirect path exists, send there
		if c.cfg.AuthFailurePath != "" {
			http.Redirect(w, r, c.cfg.AuthFailurePath, http.StatusSeeOther)
			return false
		} else {
			// stop the redirect loop here to prevent redirect chaos.
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return false
		}
	}

	return true
}

func (c Authenticator) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// verify state
	uri, ok := c.verifyState(ctx, q.Get("state"))
	if !ok {
		c.redirect(w, r)
		return
	}

	code := q.Get("code")
	if strings.TrimSpace(code) == "" {
		c.redirect(w, r)
		return
	}

	token, err := c.cfg.AuthConfig.Exchange(ctx, code)
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to exchange code")
		c.redirect(w, r)
		return
	}
	idI := token.Extra("id_token")
	if idI == nil {
		c.redirect(w, r)
		return
	}
	id, ok := idI.(string)
	if !ok {
		c.cfg.Logger.Log("message", "id_token was not a string",
			"error", "unexpected type: "+fmt.Sprintf("%T", idI))
		c.redirect(w, r)
		return
	}

	// they have authenticated, see if we can authorize them
	// via the given verifyFunc
	if okay := c.verify(w, r, id); !okay {
		return
	}

	// TODO: figure out proper way to do refresh tokens
	// grab claims so we can use the expiration on our cookie
	//claims, err := decodeClaims(id)
	//if err != nil {
	//	c.cfg.Logger.Log("error", err, "message", "unable to decode token")
	//	c.redirect(w, r)
	//	return
	//}

	// we set a cookie which expires at end of desired login period
	expire := 60 * 24 // default 1 day
	if c.cfg.LoginValidMinutes > 0 {
		expire = c.cfg.LoginValidMinutes
	}
	expireTime := time.Now().UTC().Add(time.Duration(expire) * time.Minute)

	// TODO: remove when all sorted out
	//fmt.Printf("Claims expire:  %v (from %d)\n", time.Unix(claims.Exp, 0).UTC(), claims.Exp)
	//fmt.Printf("Desired expire: %v\n", expireTime)

	http.SetCookie(w, &http.Cookie{
		Name:   c.cfg.CookieName,
		Secure: c.secureCookie,
		Value:  id,
		Domain: c.cookieDomain,
		// TODO: Default is 1 hour, which is too short, so we are improvising
		//Expires: time.Unix(claims.Exp, 0),
		Expires: expireTime,
		Path:    "/",
	})
	http.Redirect(w, r, uri, http.StatusTemporaryRedirect)
}

// LogOut can be used to clear an existing session. It will add an HTTP cookie with a -1
// "MaxAge" to the response to remove the cookie from the logged in user's browser.
func (c Authenticator) LogOut(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    c.cfg.CookieName,
		Secure:  c.secureCookie,
		Value:   "",
		Domain:  c.cookieDomain,
		Expires: time.Unix(0, 0),
		Path:    "/", // needed to ensure cookie is removed
		MaxAge:  -1,
	})
}

func (c Authenticator) verifyState(ctx context.Context, state string) (string, bool) {
	if state == "" {
		return "", false
	}
	rawState, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return "", false
	}

	var data stateData
	if c.keys == nil {
		err = json.Unmarshal(rawState, &data)
		if err != nil {
			return "", false
		}
		return data.verifiedURI()
	}

	decRes, err := c.keys.Decrypt(ctx, &kmsv1.DecryptRequest{
		Name:       c.cfg.KMSKeyName,
		Ciphertext: rawState,
	})
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to decrypt state",
			"state", state)
		return "", false
	}

	err = json.Unmarshal(decRes.Plaintext, &data)
	if err != nil {
		return "", false
	}
	return data.verifiedURI()
}

func (s stateData) verifiedURI() (string, bool) {
	// TODO: figure out proper way to do refresh tokens
	// return s.URI, time.Now().Before(s.Expiry)

	// for now, just always allow (use cookie expiration to force login
	return s.URI, true
}

type stateData struct {
	Expiry time.Time
	URI    string
	Nonce  *[24]byte
}

func newNonce() (*[24]byte, error) {
	nonce := &[24]byte{}
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nonce, errors.Wrap(err, "unable to generate nonce from rand.Reader")
	}
	return nonce, nil
}

func (c Authenticator) redirect(w http.ResponseWriter, r *http.Request) {
	state := "/" // can't be empty
	uri := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		uri += "?" + r.URL.RawQuery
	}
	// avoid redirect loops
	if strings.HasPrefix(uri, c.cfg.AuthConfig.RedirectURL) {
		uri = "/"
	}
	nonce, err := newNonce()
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to generate nonce")
		http.Error(w, "oauth error", http.StatusInternalServerError)
		return
	}
	const stateExpiryMins = 10
	stateData, err := json.Marshal(stateData{
		Expiry: time.Now().Add(stateExpiryMins * time.Minute),
		URI:    uri,
		Nonce:  nonce,
	})
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to encode state")
		http.Error(w, "oauth error", http.StatusInternalServerError)
		return
	}
	if c.keys != nil {
		encRes, err := c.keys.Encrypt(r.Context(), &kmsv1.EncryptRequest{
			Name:      c.cfg.KMSKeyName,
			Plaintext: stateData,
		})
		if err != nil {
			c.cfg.Logger.Log("error", err, "message", "unable to encrypt state")
		} else {
			stateData = encRes.Ciphertext
		}
	}
	state = base64.StdEncoding.EncodeToString(stateData)

	http.Redirect(w, r, c.cfg.AuthConfig.AuthCodeURL(state),
		http.StatusTemporaryRedirect)
}

type key int

const claimsKey key = 1

// GetUserClaims will return the Google identity claim set if it exists in the
// context. This can be used in coordination with the Authenticator.Middleware.
func GetUserClaims(ctx context.Context) (gcp.IdentityClaimSet, error) {
	var claims gcp.IdentityClaimSet
	clms := ctx.Value(claimsKey)
	if clms == nil {
		return claims, errors.New("claims not found")
	}
	return clms.(gcp.IdentityClaimSet), nil
}

func decodeClaims(token string) (gcp.IdentityClaimSet, error) {
	var claims gcp.IdentityClaimSet
	s := strings.Split(token, ".")
	if len(s) < 2 {
		return claims, errors.New("jws: invalid token received")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return claims, err
	}
	err = json.Unmarshal(decoded, &claims)
	if err != nil {
		return claims, err
	}
	return claims, nil
}
