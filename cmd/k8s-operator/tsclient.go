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
		client.Auth = &tailscale.IdentityFederation{
			ClientID: clientID,
			IDTokenFunc: func() (string, error) {
				token, err := os.ReadFile(oidcJWTPath)
				if err != nil {
					return "", err
				}

				return string(token), nil
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

