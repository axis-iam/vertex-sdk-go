// A standalone Go+React host. The optional BFF lives inside this application;
// memory is chosen explicitly and shared by all requests in this process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/axis-iam/vertex-sdk-go/authz"
	"github.com/axis-iam/vertex-sdk-go/websession"
)

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("missing configuration: %s", name)
	}
	return value
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := websession.NewMemory(websession.MemoryOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	origin, issuer, client, callback := required("APP_ORIGIN"), required("IAM_ISSUER"), required("IAM_CLIENT_ID"), required("IAM_CALLBACK_URL")
	service, err := websession.New(ctx, websession.Config{
		Issuer: issuer, Audience: required("IAM_AUDIENCE"), ClientID: client, ClientSecret: required("IAM_CLIENT_SECRET"),
		Origin: origin, CallbackURL: callback, Scopes: strings.Fields(required("IAM_SCOPES")),
		ReturnTo: "/", AllowedReturnTo: []string{"/"}, Provider: store, Workers: 1, Replicas: 1,
		AllowLoopbackHTTP: os.Getenv("APP_ALLOW_LOOPBACK_HTTP") == "true",
		PasswordResetURL:  os.Getenv("APP_PASSWORD_RESET_URL"),
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", service.Handler())
	mux.Handle("/api/documents", service.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authz.FromContext(r.Context())
		if !u.HasPermission("documents", "read") {
			http.Error(w, "forbidden", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"subject": u.Subject, "created": true})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": u.Subject, "documents": []string{"example document"}})
	})))
	mux.HandleFunc("GET /example-config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"origin": origin, "issuerUri": issuer, "clientId": client, "redirectUri": callback})
	})
	mux.Handle("/", http.FileServer(http.Dir(required("APP_WEB_DIR"))))
	server := &http.Server{Addr: required("APP_LISTEN"), Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Print("HTTP shutdown failed")
		}
	}()
	log.Print("Go BFF example ready")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
