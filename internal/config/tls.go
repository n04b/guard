package config

import "os"

// ResolveTLSMode turns "auto" into a concrete mode:
//
//   - custom, if the certificate and key files exist;
//   - acme, if an ACME e-mail is configured and every domain is public;
//   - local-ca otherwise.
func (c *Config) ResolveTLSMode() TLSMode {
	return c.resolveTLSMode(fileExists)
}

func (c *Config) resolveTLSMode(exists func(string) bool) TLSMode {
	t := c.TLS.TLS
	if t.Mode != TLSAuto {
		return t.Mode
	}
	if exists(t.Custom.Certificate) && exists(t.Custom.PrivateKey) {
		return TLSCustom
	}
	if t.ACME.Email != "" {
		public := true
		for _, h := range c.AllHostnames() {
			if !IsPublicHostname(h) {
				public = false
				break
			}
		}
		if public {
			return TLSACME
		}
	}
	return TLSLocalCA
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
