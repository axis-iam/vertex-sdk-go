package main

import (
	"errors"
	"flag"
	"os"
)

type commonFlags struct {
	endpoint     string
	clientID     string
	clientSecret string
}

func (f *commonFlags) attach(fs *flag.FlagSet) {
	fs.StringVar(&f.endpoint, "endpoint", os.Getenv("IAM_ENDPOINT"), "IAM base URL")
	fs.StringVar(&f.clientID, "client-id", os.Getenv("IAM_CLIENT_ID"), "ApplicationClient.clientId from a WEB/M2M confidential client")
	fs.StringVar(&f.clientSecret, "client-secret", os.Getenv("IAM_CLIENT_SECRET"), "WEB/M2M confidential ApplicationClient secret")
}

func (f *commonFlags) validate() error {
	if f.endpoint == "" {
		return errors.New("missing --endpoint (or IAM_ENDPOINT)")
	}
	if f.clientID == "" {
		return errors.New("missing --client-id (or IAM_CLIENT_ID)")
	}
	if f.clientSecret == "" {
		return errors.New("missing --client-secret (or IAM_CLIENT_SECRET)")
	}
	return nil
}
