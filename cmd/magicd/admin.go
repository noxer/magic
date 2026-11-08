package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/client"
	"github.com/noxer/magic/identity"
	"github.com/noxer/magic/provider"
)

func adminCommand(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory of the running magicd")
	scopes := fs.String("scopes", "", "comma-separated capabilities (default: all offered)")
	name := fs.String("name", "", "client name (token)")
	ttl := fs.Duration("ttl", 10*time.Minute, "ticket validity")
	fs.Parse(args)

	data, err := os.ReadFile(filepath.Join(*stateDir, "admin.json"))
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("magicd is not running (no admin.json in " + *stateDir + ")")
	} else if err != nil {
		return err
	}
	var info adminInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return err
	}
	if cmd == "info" {
		fmt.Printf("name:        %s\nid:          %s\nfingerprint: %s\nlocal url:   %s\n", info.Name, info.ID, info.Fingerprint, info.URL)
		if info.LANPort != 0 {
			fmt.Printf("lan port:    %d\n", info.LANPort)
		}
		return nil
	}
	c := &client.Client{BaseURL: info.URL, Token: info.Token}
	if c.HTTP, err = client.HTTPClient(info.URL, identity.Pin{ID: info.ID}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := magic.APIPrefix + "/admin"
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()

	switch cmd {
	case "pairings":
		var resp struct{ Pairings []provider.Pending }
		if err := c.Do(ctx, "GET", p+"/pairings", nil, &resp); err != nil {
			return err
		}
		if len(resp.Pairings) == 0 {
			fmt.Println("no pending pairing requests")
			return nil
		}
		fmt.Fprintln(tw, "ID\tCLIENT\tDEVICE\tSCOPES\tCODE\tEXPIRES")
		for _, r := range resp.Pairings {
			code := formatCode(r.Code)
			if r.Ticket != "" {
				code = "(ticket)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Client.Name, r.Client.Device, joinCaps(r.Scopes), code, r.ExpiresAt.Local().Format("15:04:05"))
		}
	case "deny":
		if fs.NArg() != 1 {
			return errors.New("usage: magicd deny <pairing-id>")
		}
		return c.Do(ctx, "DELETE", p+"/pairings/"+url.PathEscape(fs.Arg(0)), nil, nil)
	case "ticket":
		var t provider.Ticket
		if err := c.Do(ctx, "POST", p+"/tickets", map[string]any{"scopes": splitCaps(*scopes), "ttl_seconds": int(ttl.Seconds())}, &t); err != nil {
			return err
		}
		fmt.Printf("Pairing code: %s   (one-time, valid until %s, scopes: %s)\n", formatCode(t.Code), t.ExpiresAt.Local().Format("15:04:05"), joinCaps(t.Scopes))
		if info.LANPort != 0 {
			host := primaryIP()
			u := url.URL{Scheme: "magic", Host: net.JoinHostPort(host, fmt.Sprint(info.LANPort)), Path: "/pair",
				RawQuery: url.Values{"id": {info.ID}, "ticket": {t.ID}, "code": {t.Code}}.Encode()}
			fmt.Printf("Pairing URI:  %s\n\nOn the other device run:\n  magic pair '%s'\n", u.String(), u.String())
		}
	case "token":
		if *name == "" {
			return errors.New("usage: magicd token -name <client name> [-scopes chat,embeddings]")
		}
		var g magic.Grant
		if err := c.Do(ctx, "POST", p+"/tokens", map[string]any{"name": *name, "scopes": splitCaps(*scopes)}, &g); err != nil {
			return err
		}
		fmt.Printf("token:       %s\nscopes:      %s\nprovider id: %s\n\nConfigure the client with:\n  MAGIC_PROVIDER=https://%s:%d#%s\n  MAGIC_TOKEN=%s\n",
			g.Token, joinCaps(g.Scopes), info.ID, primaryIP(), info.LANPort, info.ID, g.Token)
	case "clients":
		var resp struct{ Clients []provider.Client }
		if err := c.Do(ctx, "GET", p+"/clients", nil, &resp); err != nil {
			return err
		}
		fmt.Fprintln(tw, "ID\tKIND\tNAME\tDEVICE\tSCOPES\tSINCE")
		for _, cl := range resp.Clients {
			sc := joinCaps(cl.Scopes)
			if cl.Admin {
				sc = "admin"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", cl.ID, cl.Kind, cl.Info.Name, cl.Info.Device, sc, cl.CreatedAt.Local().Format("2006-01-02 15:04"))
		}
	case "revoke":
		if fs.NArg() != 1 {
			return errors.New("usage: magicd revoke <client-id>")
		}
		return c.Do(ctx, "DELETE", p+"/clients/"+url.PathEscape(fs.Arg(0)), nil, nil)
	}
	return nil
}

func splitCaps(s string) []magic.Capability {
	var out []magic.Capability
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, magic.Capability(c))
		}
	}
	return out
}

// primaryIP guesses the LAN address other devices can reach.
func primaryIP() string {
	if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil { // no packets are sent
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).IP.String()
	}
	if h, err := os.Hostname(); err == nil {
		return h + ".local"
	}
	return "localhost"
}
