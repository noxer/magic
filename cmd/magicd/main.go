// Command magicd is the Magic reference provider. It puts an existing
// OpenAI-compatible inference server (Ollama, llama.cpp, LM Studio, vLLM, ...)
// on the local network and computer with discovery, pairing and
// capability-scoped access tokens.
//
// Usage:
//
//	magicd [serve] [flags]        run the provider
//	magicd pairings               list pending pairing requests and their codes
//	magicd deny <pairing-id>      reject a pending pairing request
//	magicd ticket [-scopes ...]   create a one-time pairing code (for QR codes / headless clients)
//	magicd token -name N [...]    issue a long-lived token for scripts and services
//	magicd clients                list authorized clients
//	magicd revoke <client-id>     revoke a client's access
//	magicd info                   print the provider identity
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/discovery"
	"github.com/noxer/magic/discovery/local"
	"github.com/noxer/magic/identity"
	"github.com/noxer/magic/internal/backend"
	"github.com/noxer/magic/provider"
)

const version = "0.1.0"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "pairings", "deny", "ticket", "token", "clients", "revoke", "info":
		err = adminCommand(cmd, args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "version":
		fmt.Println("magicd", version)
	default:
		err = fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "magicd:", err)
		os.Exit(1)
	}
}

const usage = `usage: magicd [command] [flags]

commands:
  serve                  run the provider (default)
  pairings               list pending pairing requests and their codes
  deny <pairing-id>      reject a pending pairing request
  ticket [-scopes s,..]  create a one-time pairing code and pairing URI
  token -name N          issue a long-lived token (-scopes s,..)
  clients                list authorized clients
  revoke <client-id>     revoke a client's access
  info                   print the provider identity

run "magicd serve -h" for provider flags
`

func defaultStateDir() string {
	if d := os.Getenv("MAGICD_STATE"); d != "" {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "magicd")
	}
	return ".magicd"
}

// adminInfo lets admin subcommands reach the running daemon.
type adminInfo struct {
	URL         string `json:"url"`
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	LANPort     int    `json:"lan_port,omitempty"`
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	host, _ := os.Hostname()
	var (
		name         = fs.String("name", host, "provider name shown to users")
		listen       = fs.String("listen", ":8765", "LAN listen address (TLS); empty to disable")
		localListen  = fs.String("local", "127.0.0.1:0", "loopback listen address (plain HTTP for local apps); empty to disable")
		backendURL   = fs.String("backend", "", "OpenAI-compatible backend URL (default: auto-detect Ollama, LM Studio, llama.cpp, vLLM, Jan)")
		backendKey   = fs.String("backend-key", os.Getenv("MAGICD_BACKEND_KEY"), "API key for the backend")
		stateDir     = fs.String("state", defaultStateDir(), "state directory (identity, clients)")
		noMDNS       = fs.Bool("no-mdns", false, "do not advertise on the local network")
		publicModels = fs.Bool("public-models", false, "show model details to unauthenticated clients")
		locality     = fs.String("locality", "device", "where the backend processes data: device, network or cloud")
		modelsFile   = fs.String("models", "", "JSON file with model descriptions overriding auto-detection")
	)
	fs.Parse(args)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	loc := magic.Locality(*locality)
	if loc != magic.LocalityDevice && loc != magic.LocalityNetwork && loc != magic.LocalityCloud {
		return fmt.Errorf("invalid -locality %q", *locality)
	}

	// Backend.
	var be *backend.Backend
	var err error
	if *backendURL != "" {
		be, err = backend.New(*backendURL, *backendKey)
	} else {
		var kind string
		be, kind, err = backend.Detect(context.Background())
		if err == nil {
			log.Info("detected backend", "kind", kind, "url", be.Base.String())
		}
	}
	if err != nil {
		return err
	}
	be.Locality = loc
	if *modelsFile != "" {
		data, err := os.ReadFile(*modelsFile)
		if err != nil {
			return err
		}
		var list []magic.Model
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("%s: %w", *modelsFile, err)
		}
		be.Overrides = map[string]magic.Model{}
		for _, m := range list {
			be.Overrides[m.ID] = m
		}
	}

	// Identity and state.
	id, err := identity.LoadOrCreate(filepath.Join(*stateDir, "identity"), []string{host + ".local", "localhost", "127.0.0.1", "::1"})
	if err != nil {
		return err
	}
	store, err := provider.OpenStore(filepath.Join(*stateDir, "clients.json"))
	if err != nil {
		return err
	}
	srv, err := provider.New(provider.Config{
		Identity:     id,
		Name:         *name,
		Software:     &magic.SoftwareInfo{Name: "magicd", Version: version, URL: "https://github.com/noxer/magic"},
		Locality:     loc,
		Store:        store,
		Models:       be.Models,
		Backend:      be.Handler(),
		PublicModels: *publicModels,
		Logger:       log,
		OnPairing:    showPairing,
		OnPaired: func(c provider.Client) {
			fmt.Fprintf(os.Stderr, "\n  ✔ %q is now paired (scopes: %s)\n\n", c.Info.Name, joinCaps(c.Scopes))
		},
	})
	if err != nil {
		return err
	}
	caps := srv.Capabilities(context.Background())
	log.Info("provider ready", "id", id.ID(), "name", *name, "capabilities", joinCaps(caps), "models", len(srv.Models(context.Background())))

	// Local tokens: replaced on every start.
	if err := store.RevokeKind(provider.KindLocal); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 2)
	var servers []*http.Server
	lanPort := 0

	if *listen != "" {
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		hs := &http.Server{Handler: srv.Handler(provider.Options{}), TLSConfig: id.TLSConfig(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: slogErrorLog(log)}
		servers = append(servers, hs)
		go func() { errc <- hs.ServeTLS(ln, "", "") }()
		port := ln.Addr().(*net.TCPAddr).Port
		log.Info("serving LAN", "addr", ln.Addr().String(), "tls", true)
		if ip := ln.Addr().(*net.TCPAddr).IP; !ip.IsUnspecified() && !*noMDNS {
			// mDNS advertises all interface addresses; that is only right for wildcard listeners.
			log.Warn("not advertising via mDNS: -listen is bound to a specific address", "addr", ip.String())
		} else if !*noMDNS {
			r, err := discovery.Advertise(discovery.Advertisement{Name: *name, Port: port, ID: id.ID(), Capabilities: caps, Auth: []string{magic.AuthPairing, magic.AuthToken}})
			if err != nil {
				log.Warn("mDNS advertisement failed", "err", err)
			} else {
				defer r.Close()
				log.Info("advertising via mDNS", "service", magic.ServiceType, "instance", *name)
			}
		}
		lanPort = port
	}

	if *localListen != "" {
		ln, err := net.Listen("tcp", *localListen)
		if err != nil {
			return err
		}
		if a := ln.Addr().(*net.TCPAddr); !a.IP.IsLoopback() {
			return errors.New("-local must be a loopback address")
		}
		hs := &http.Server{Handler: srv.Handler(provider.Options{Loopback: true}), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, hs)
		go func() { errc <- hs.Serve(ln) }()
		localURL := "http://" + ln.Addr().String()
		log.Info("serving local apps", "url", localURL)

		// Token for local apps, in a file only this user can read.
		tokDir := filepath.Dir(local.UserDir())
		_, tok, err := store.Issue(provider.KindLocal, magic.ClientInfo{Name: "local apps"}, magic.Registered, false)
		if err != nil {
			return err
		}
		tokFile := filepath.Join(tokDir, id.ID()+".token")
		if err := provider.WriteFileAtomic(tokFile, []byte(tok+"\n"), 0o600); err != nil {
			return err
		}
		defer os.Remove(tokFile)
		remove, err := local.Publish(local.UserDir(), magic.Beacon{
			ID: id.ID(), Name: *name, URL: localURL, Fingerprint: id.Fingerprint.String(), TokenFile: tokFile, Capabilities: caps,
		})
		if err != nil {
			return err
		}
		defer remove()

		// Admin access for the magicd subcommands.
		_, adminTok, err := store.Issue(provider.KindLocal, magic.ClientInfo{Name: "magicd admin"}, nil, true)
		if err != nil {
			return err
		}
		info := adminInfo{URL: localURL, Token: adminTok, Fingerprint: id.Fingerprint.String(), ID: id.ID(), Name: *name, LANPort: lanPort}
		data, _ := json.MarshalIndent(info, "", "  ")
		adminFile := filepath.Join(*stateDir, "admin.json")
		if err := provider.WriteFileAtomic(adminFile, data, 0o600); err != nil {
			return err
		}
		defer os.Remove(adminFile)
	}
	if len(servers) == 0 {
		return errors.New("nothing to serve: both -listen and -local are empty")
	}

	fmt.Fprintf(os.Stderr, "\n  magicd %s — %q (id %s)\n  Pair a device with:  magic pair %s\n\n", version, *name, id.ID(), id.ID())

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, hs := range servers {
		hs.Shutdown(sctx)
	}
	return nil
}

func showPairing(p provider.Pending) {
	device := ""
	if p.Client.Device != "" {
		device = " on " + p.Client.Device
	}
	fmt.Fprintf(os.Stderr, "\n  ┌ Pairing request from %q%s\n  │ wants: %s\n  │ Code:  %s   (valid until %s)\n  └ Enter this code on the device to allow access. Ignore to deny.\n\n",
		p.Client.Name, device, joinCaps(p.Scopes), formatCode(p.Code), p.ExpiresAt.Local().Format("15:04:05"))
}

func formatCode(c string) string {
	if len(c) == 8 {
		return c[:4] + "-" + c[4:]
	}
	return c
}

func joinCaps(cs []magic.Capability) string {
	if len(cs) == 0 {
		return "(none)"
	}
	s := make([]string, len(cs))
	for i, c := range cs {
		s[i] = string(c)
	}
	return strings.Join(s, ", ")
}

func slogErrorLog(l *slog.Logger) *log.Logger {
	return slog.NewLogLogger(l.Handler(), slog.LevelDebug)
}
