// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
)

const (
	oidcJWTPath = "/var/run/secrets/tailscale/serviceaccount/token"
)

func newTSClient(logger *zap.SugaredLogger, clientID, clientIDPath, clientSecretPath, loginServer, customTokenURL string) (*tailscale.Client, error) {
	baseURL := ipn.DefaultControlURL
	if loginServer != "" {
		baseURL = loginServer
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	client := &tailscale.Client{
		UserAgent: "tailscale-k8s-operator",
		BaseURL:   base,
	}

	if clientID == "" {
		// Use static client credentials mounted to disk.
		clientIDBytes, err := os.ReadFile(clientIDPath)
		if err != nil {
			return nil, fmt.Errorf("error reading client ID %q: %w", clientIDPath, err)
		}
		clientSecretBytes, err := os.ReadFile(clientSecretPath)
		if err != nil {
			return nil, fmt.Errorf("reading client secret %q: %w", clientSecretPath, err)
		}
		if customTokenURL != "" {
			client.Auth = &customOAuth{
				ClientID:     string(clientIDBytes),
				ClientSecret: string(clientSecretBytes),
				TokenURL:     customTokenURL,
			}
		} else {
			client.Auth = &tailscale.OAuth{
				ClientID:     string(clientIDBytes),
				ClientSecret: string(clientSecretBytes),
			}
		}
	} else {
		// Use workload identity federation.
		tokenSrc := &jwtTokenSource{
			logger:  logger,
			jwtPath: oidcJWTPath,
			baseCfg: clientcredentials.Config{
				ClientID: clientID,
				TokenURL: fmt.Sprintf("%s%s", baseURL, "/api/v2/oauth/token-exchange"),
			},
		}

		client.Auth = &tailscale.IdentityFederation{
			ClientID: clientID,
			IDTokenFunc: func() (string, error) {
				token, err := tokenSrc.Token()
				if err != nil {
					return "", err
				}

				return token.AccessToken, nil
			},
		}
	}

	return client, nil
}

// customOAuth implements the [tailscale.Auth] interface with a fully-configurable token URL.
type customOAuth struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
}

func (o *customOAuth) HTTPClient(orig *http.Client, _ string) *http.Client {
	cfg := clientcredentials.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		TokenURL:     o.TokenURL,
	}
	tokenSource := cfg.TokenSource(context.Background())
	return &http.Client{
		Transport:     &oauth2.Transport{Base: orig.Transport, Source: oauth2.ReuseTokenSource(nil, tokenSource)},
		CheckRedirect: orig.CheckRedirect,
		Jar:           orig.Jar,
		Timeout:       orig.Timeout,
	}
}

// jwtTokenSource implements the [oauth2.TokenSource] interface, but with the
// ability to regenerate a fresh underlying token source each time a new value
// of the JWT parameter is needed due to expiration.
type jwtTokenSource struct {
	logger  *zap.SugaredLogger
	jwtPath string                   // Path to the file containing an automatically refreshed JWT.
	baseCfg clientcredentials.Config // Holds config that doesn't change for the lifetime of the process.

	mu         sync.Mutex         // Guards underlying.
	underlying oauth2.TokenSource // The oauth2 client implementation. Does its own separate caching of the access token.
}

func (s *jwtTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.underlying != nil {
		t, err := s.underlying.Token()
		if err == nil && t != nil && t.Valid() {
			return t, nil
		}
	}

	s.logger.Debugf("Refreshing JWT from %s", s.jwtPath)
	tk, err := os.ReadFile(s.jwtPath)
	if err != nil {
		return nil, fmt.Errorf("error reading JWT from %q: %w", s.jwtPath, err)
	}

	// Shallow copy of the base config.
	credentials := s.baseCfg
	credentials.EndpointParams = map[string][]string{
		"jwt": {string(tk)},
	}

	src := credentials.TokenSource(context.Background())
	s.underlying = oauth2.ReuseTokenSourceWithExpiry(nil, src, time.Minute)
	return s.underlying.Token()
}
