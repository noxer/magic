// Command magic is the Magic reference client. It discovers providers on
// this computer and the local network, pairs with them, and uses their
// capabilities. It can also expose a paired provider as a plain
// OpenAI-compatible endpoint on localhost for tools that do not speak Magic.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/client"
	"github.com/noxer/magic/discovery"
	"github.com/noxer/magic/identity"
	"github.com/noxer/magic/provider"
)

const usage = `usage: magic <command> [flags] [args]

commands:
  discover [-cap C] [-wait D]     find providers on this computer and the network
  pair <provider|url|magic://…>   pair with a provider using the code it shows
  list                            list paired providers
  models [provider]               list models and capabilities
  chat [-p provider] [-m model] <prompt…>
  embed [-p provider] [-m model] <text…>
  proxy [-p provider] [-listen addr]
                                  serve a paired provider as an OpenAI-compatible
                                  endpoint on localhost for existing tools
  forget <provider>               unpair and delete the credential

A provider can be named by ID (or a unique ID prefix), by name, or by URL.
Environment: MAGIC_PROVIDER (URL[#id]), MAGIC_TOKEN, MAGIC_CREDENTIALS.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "discover":
		err = cmdDiscover(ctx, args)
	case "pair":
		err = cmdPair(ctx, args)
	case "list":
		err = cmdList()
	case "models":
		err = cmdModels(ctx, args)
	case "chat":
		err = cmdChat(ctx, args)
	case "embed":
		err = cmdEmbed(ctx, args)
	case "proxy":
		err = cmdProxy(ctx, args)
	case "forget":
		err = cmdForget(ctx, args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "magic:", strings.TrimPrefix(err.Error(), "magic: "))
		os.Exit(1)
	}
}

func credentials() (*client.Credentials, error) {
	p, err := client.DefaultCredentialsPath()
	if err != nil {
		return nil, err
	}
	return client.OpenCredentials(p)
}

func cmdDiscover(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	capability := fs.String("cap", "", "only providers offering this capability")
	wait := fs.Duration("wait", 2*time.Second, "how long to listen")
	fs.Parse(args)
	creds, err := credentials()
	if err != nil {
		return err
	}
	ps, err := discovery.Discover(ctx, *wait, discovery.Options{Capability: magic.Capability(*capability)})
	if err != nil {
		return err
	}
	if len(ps) == 0 {
		fmt.Println("no providers found")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tID\tCAPABILITIES\tVIA\tACCESS\tURL")
	for _, p := range ps {
		access := "-"
		switch {
		case creds.Get(p.ID) != nil:
			access = "paired"
		case p.TokenFile != "":
			if _, err := os.Stat(p.TokenFile); err == nil {
				access = "local"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.ID, joinCaps(p.Capabilities), strings.Join(p.Sources, ","), access, first(p.URLs))
	}
	return tw.Flush()
}

// target is a resolved provider reference.
type target struct {
	provider discovery.Provider
	ticket   string
	code     string
}

// resolve turns a user-supplied reference into a provider.
func resolve(ctx context.Context, ref string, creds *client.Credentials) (*target, error) {
	if ref == "" {
		if p, err := discovery.FromEnv(); err != nil || p != nil {
			if p != nil {
				return &target{provider: *p}, nil
			}
			return nil, err
		}
		paired := creds.List()
		ps, _ := discovery.Discover(ctx, 300*time.Millisecond, discovery.Options{NoMDNS: true})
		switch {
		case len(paired) == 1:
			ref = paired[0].ProviderID
		case len(paired) == 0 && len(ps) == 1:
			return &target{provider: ps[0]}, nil
		default:
			return nil, errors.New("several providers available; name one (see magic list / magic discover)")
		}
	}
	if strings.HasPrefix(ref, "magic://") {
		u, err := url.Parse(ref)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		if !identity.ValidID(q.Get("id")) {
			return nil, errors.New("pairing URI lacks a valid id")
		}
		return &target{
			provider: discovery.Provider{ID: q.Get("id"), URLs: []string{"https://" + u.Host}},
			ticket:   q.Get("ticket"),
			code:     q.Get("code"),
		}, nil
	}
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		p, err := discovery.ParseURL(ref)
		if err != nil {
			return nil, err
		}
		return &target{provider: *p}, nil
	}
	match := func(id, name string) bool {
		r := strings.ToLower(ref)
		return strings.HasPrefix(id, r) && len(r) >= 4 || strings.EqualFold(name, ref)
	}
	// Discovery gives current addresses; credentials remember old ones.
	ps, _ := discovery.Discover(ctx, 1500*time.Millisecond, discovery.Options{})
	var found []discovery.Provider
	for _, p := range ps {
		if match(p.ID, p.Name) {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		for _, c := range creds.List() {
			if match(c.ProviderID, c.Name) {
				found = append(found, discovery.Provider{ID: c.ProviderID, Name: c.Name, URLs: c.URLs})
			}
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("provider %q not found", ref)
	case 1:
		return &target{provider: found[0]}, nil
	}
	return nil, fmt.Errorf("%q is ambiguous; use the provider ID", ref)
}

func cmdPair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	scopes := fs.String("scopes", "", "comma-separated capabilities to request (default: all offered)")
	name := fs.String("name", "magic CLI", "client name shown to the provider's operator")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: magic pair <provider|url|magic://…>")
	}
	creds, err := credentials()
	if err != nil {
		return err
	}
	t, err := resolve(ctx, fs.Arg(0), creds)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	var lastErr error
	for _, u := range t.provider.URLs {
		if strings.HasPrefix(u, "http://") && t.provider.Fingerprint.IsZero() {
			continue
		}
		label := t.provider.Name
		if label == "" {
			label = u
		}
		cred, err := client.Pair(ctx, client.PairOptions{
			URL:         u,
			ExpectID:    t.provider.ID,
			Fingerprint: t.provider.Fingerprint,
			Client:      magic.ClientInfo{Name: *name, Software: "magic/0.1.0", Device: host},
			Scopes:      splitCaps(*scopes),
			Ticket:      t.ticket,
			Code: func(ctx context.Context, s magic.PairingStarted) (string, error) {
				if t.code != "" {
					return t.code, nil
				}
				if t.provider.ID != "" {
					label += " (id " + short(t.provider.ID) + ")"
				}
				fmt.Fprintf(os.Stderr, "Pairing with %s.\nEnter the %d-digit code shown by the provider: ", label, s.CodeDigits)
				return readLine(ctx)
			},
		})
		if err != nil {
			var oe *net.OpError
			if errors.As(err, &oe) {
				lastErr = err
				continue // try the next address
			}
			return err
		}
		if cred.Name == "" {
			cred.Name = t.provider.Name
		}
		if err := creds.Put(cred); err != nil {
			return err
		}
		fmt.Printf("Paired with %q (id %s). Granted: %s\n", cred.Name, cred.ProviderID, joinCaps(cred.Scopes))
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable address for provider")
	}
	return lastErr
}

func readLine(ctx context.Context) (string, error) {
	ch := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		ch <- strings.TrimSpace(s)
	}()
	select {
	case s := <-ch:
		return s, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func cmdList() error {
	creds, err := credentials()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tID\tSCOPES\tPAIRED\tLAST URL")
	for _, c := range creds.List() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.Name, c.ProviderID, joinCaps(c.Scopes), c.PairedAt.Local().Format("2006-01-02"), first(c.URLs))
	}
	return tw.Flush()
}

// connect resolves ref and returns an authenticated client.
func connect(ctx context.Context, ref string) (*client.Client, *discovery.Provider, error) {
	creds, err := credentials()
	if err != nil {
		return nil, nil, err
	}
	t, err := resolve(ctx, ref, creds)
	if err != nil {
		return nil, nil, err
	}
	p := t.provider
	if tok := os.Getenv("MAGIC_TOKEN"); tok != "" && creds.Get(p.ID) == nil && p.ID != "" {
		c, err := client.New(first(p.URLs), &client.Credential{ProviderID: p.ID, Token: tok})
		return c, &p, err
	}
	c, err := client.Connect(ctx, p, creds)
	if errors.Is(err, client.ErrNotPaired) {
		return nil, nil, fmt.Errorf("not paired with %s; run: magic pair %s", p.Name, p.ID)
	}
	if err == nil {
		if cr := creds.Get(p.ID); cr != nil && !contains(cr.URLs, c.BaseURL) {
			cr.URLs = append([]string{c.BaseURL}, cr.URLs...)
			creds.Put(cr)
		}
	}
	return c, &p, err
}

func cmdModels(ctx context.Context, args []string) error {
	c, _, err := connect(ctx, first(args))
	if err != nil {
		return err
	}
	d, err := c.Descriptor(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%s (id %s, %s)\n\n", d.Provider.Name, d.Provider.ID, d.Provider.Locality)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MODEL\tCAPABILITIES\tFEATURES\tCONTEXT\tLOCALITY")
	for _, m := range d.Models {
		ctxLen := "-"
		if m.ContextLength > 0 {
			ctxLen = fmt.Sprint(m.ContextLength)
		}
		feats := make([]string, len(m.Features))
		for i, f := range m.Features {
			feats[i] = string(f)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", m.ID, joinCaps(m.Capabilities), strings.Join(feats, ","), ctxLen, m.Locality)
	}
	return tw.Flush()
}

// pickModel returns the requested model or the first one offering capability.
func pickModel(ctx context.Context, c *client.Client, model string, capability magic.Capability) (string, error) {
	if model != "" {
		return model, nil
	}
	d, err := c.Descriptor(ctx)
	if err != nil {
		return "", err
	}
	for _, m := range d.Models {
		if m.Has(capability) {
			return m.ID, nil
		}
	}
	return "", fmt.Errorf("provider offers no %s model", capability)
}

func cmdChat(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("chat", flag.ExitOnError)
	prov := fs.String("p", "", "provider")
	model := fs.String("m", "", "model (default: first chat model)")
	system := fs.String("system", "", "system prompt")
	fs.Parse(args)
	prompt := strings.Join(fs.Args(), " ")
	if prompt == "" || prompt == "-" {
		b, _ := io.ReadAll(os.Stdin)
		prompt = string(b)
	}
	c, _, err := connect(ctx, *prov)
	if err != nil {
		return err
	}
	m, err := pickModel(ctx, c, *model, magic.Chat)
	if err != nil {
		return err
	}
	var msgs []client.ChatMessage
	if *system != "" {
		msgs = append(msgs, client.ChatMessage{Role: "system", Content: *system})
	}
	msgs = append(msgs, client.ChatMessage{Role: "user", Content: prompt})
	reply, err := c.Chat(ctx, m, msgs)
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimSpace(reply))
	return nil
}

func cmdEmbed(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("embed", flag.ExitOnError)
	prov := fs.String("p", "", "provider")
	model := fs.String("m", "", "model (default: first embeddings model)")
	fs.Parse(args)
	c, _, err := connect(ctx, *prov)
	if err != nil {
		return err
	}
	m, err := pickModel(ctx, c, *model, magic.Embeddings)
	if err != nil {
		return err
	}
	vecs, err := c.Embed(ctx, m, []string{strings.Join(fs.Args(), " ")})
	if err != nil {
		return err
	}
	for _, v := range vecs {
		fmt.Printf("%d dimensions: %v\n", len(v), preview(v))
	}
	return nil
}

func preview(v []float64) string {
	if len(v) <= 6 {
		return fmt.Sprint(v)
	}
	return fmt.Sprintf("%.4f … %.4f", v[:3], v[len(v)-3:])
}

func cmdProxy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	prov := fs.String("p", "", "provider")
	listen := fs.String("listen", "127.0.0.1:7777", "loopback address to listen on")
	fs.Parse(args)
	c, p, err := connect(ctx, *prov)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		ln.Close()
		return errors.New("-listen must be a loopback address")
	}
	key := provider.NewToken()
	target, _ := url.Parse(c.BaseURL)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header.Set("Authorization", "Bearer "+c.Token)
		},
		Transport:     c.HTTP.Transport,
		FlushInterval: -1,
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); !(host == "localhost" || ip != nil && ip.IsLoopback()) {
			http.Error(w, "invalid Host", http.StatusMisdirectedRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":{"message":"invalid API key for magic proxy","type":"unauthorized"}}`)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			http.NotFound(w, r)
			return
		}
		rp.ServeHTTP(w, r)
	})
	name := p.Name
	if name == "" {
		name = p.ID
	}
	fmt.Printf("Serving %s as an OpenAI-compatible API. Point your tools at:\n\n  OPENAI_BASE_URL=http://%s/v1\n  OPENAI_API_KEY=%s\n\nPress Ctrl+C to stop.\n", name, ln.Addr(), key)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func cmdForget(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: magic forget <provider>")
	}
	creds, err := credentials()
	if err != nil {
		return err
	}
	var cred *client.Credential
	for _, c := range creds.List() {
		if strings.HasPrefix(c.ProviderID, strings.ToLower(args[0])) && len(args[0]) >= 4 || strings.EqualFold(c.Name, args[0]) {
			cred = c
		}
	}
	if cred == nil {
		return fmt.Errorf("not paired with %q", args[0])
	}
	if c, _, err := connect(ctx, cred.ProviderID); err == nil {
		if err := c.Unpair(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not revoke the token at the provider:", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "warning: provider unreachable; the token stays valid there until revoked by its operator")
	}
	return creds.Delete(cred.ProviderID)
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

func joinCaps(cs []magic.Capability) string {
	if len(cs) == 0 {
		return "-"
	}
	s := make([]string, len(cs))
	for i, c := range cs {
		s[i] = string(c)
	}
	return strings.Join(s, ",")
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
