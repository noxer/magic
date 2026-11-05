package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/noxer/magic"
	"github.com/noxer/magic/discovery"
	"github.com/noxer/magic/discovery/local"
	"github.com/noxer/magic/identity"
)

// ErrNotPaired is returned by Connect when no credential is available.
var ErrNotPaired = errors.New("magic: not paired with this provider")

// Connect returns a client for a discovered provider. It uses, in order, a
// stored credential (creds may be nil) or the local token file of a provider
// on this computer, and tries each of the provider's URLs until one answers.
func Connect(ctx context.Context, p discovery.Provider, creds *Credentials) (*Client, error) {
	var cred *Credential
	if creds != nil {
		cred = creds.Get(p.ID)
	}
	if cred == nil && p.TokenFile != "" && !p.Fingerprint.IsZero() {
		if tok, err := local.ReadToken(magic.Beacon{TokenFile: p.TokenFile}); err == nil {
			cred = &Credential{ProviderID: p.ID, Name: p.Name, Fingerprint: p.Fingerprint, Token: tok}
		}
	}
	if cred == nil {
		return nil, ErrNotPaired
	}
	urls := append([]string{}, p.URLs...)
	for _, u := range cred.URLs {
		if !contains(urls, u) {
			urls = append(urls, u)
		}
	}
	var errs []error
	for _, u := range urls {
		c, err := New(u, cred)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err = c.Session(cctx)
		cancel()
		if err == nil {
			return c, nil
		}
		if errors.Is(err, identity.ErrPinMismatch) || strings.Contains(err.Error(), identity.ErrPinMismatch.Error()) {
			err = fmt.Errorf("%s: %w (the provider's key changed, or someone is impersonating it)", u, identity.ErrPinMismatch)
		}
		errs = append(errs, fmt.Errorf("%s: %w", u, err))
	}
	if len(errs) == 0 {
		return nil, errors.New("magic: provider has no known address")
	}
	return nil, errors.Join(errs...)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
