// +build alttls

package https

import (
	"crypto/tls"

	"github.com/mholt/caddy/server"
)

// setDefaultTLSParams sets the default TLS cipher suites, protocol versions,
// and server preferences of a server.Config if they were not previously set
// (it does not overwrite; only fills in missing values). It will also set the
// port to 443 if not already set, TLS is enabled, TLS is manual, and the host
// does not equal localhost.
func setDefaultTLSParams(c *server.Config) {
	// If no ciphers provided, use default list
	if len(c.TLS.Ciphers) == 0 {
		c.TLS.Ciphers = defaultCiphers
	}

	// Not a cipher suite, but still important for mitigating protocol downgrade attacks
	// (prepend since having it at end breaks http2 due to non-h2-approved suites before it)
	c.TLS.Ciphers = append([]uint16{tls.TLS_FALLBACK_SCSV}, c.TLS.Ciphers...)

	// Set default protocol min and max versions - must balance compatibility and security
	if c.TLS.ProtocolMinVersion == 0 {
		c.TLS.ProtocolMinVersion = tls.VersionTLS10
	}
	if c.TLS.ProtocolMaxVersion == 0 {
		c.TLS.ProtocolMaxVersion = tls.VersionTLS12
	}

	// Prefer server cipher suites
	c.TLS.PreferServerCipherSuites = true

	// PreferServerCipherSuites enables the cipher reordering option.
	c.TLS.ReorderCipherSuites = PreferChaChaIfFirst

	// Default TLS port is 443; only use if port is not manually specified,
	// TLS is enabled, and the host is not localhost
	if c.Port == "" && c.TLS.Enabled && (!c.TLS.Manual || c.TLS.OnDemand) && c.Host != "localhost" {
		c.Port = "443"
	}
}

// Map of supported protocols.
// SSLv3 will be not supported in future release.
// HTTP/2 only supports TLS 1.2 and higher.
var supportedProtocols = map[string]uint16{
	"ssl3.0": tls.VersionSSL30,
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
}

// Map of supported ciphers, used only for parsing config.
//
// Note that, at time of writing, HTTP/2 blacklists 276 cipher suites,
// including all but two of the suites below (the two GCM suites).
// See https://http2.github.io/http2-spec/#BadCipherSuites
//
// TLS_FALLBACK_SCSV is not in this list because we manually ensure
// it is always added (even though it is not technically a cipher suite).
//
// This map, like any map, is NOT ORDERED. Do not range over this map.
var supportedCiphersMap = map[string]uint16{
	"ECDHE-RSA-AES256-GCM-SHA384":          tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-AES256-GCM-SHA384":        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES128-GCM-SHA256":          tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES128-GCM-SHA256":        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES128-CBC-SHA":             tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-AES256-CBC-SHA":             tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES256-CBC-SHA":           tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES128-CBC-SHA":           tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"ECDHE-ECDSA-CHACHA20-POLY1305-SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-RSA-CHACHA20-POLY1305-SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"DHE-RSA-AES128-GCM-SHA256":            tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	"DHE-RSA-AES256-GCM-SHA384":            tls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	"DHE-RSA-AES128-CBC-SHA256":            tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	"DHE-RSA-AES256-CBC-SHA256":            tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	"DHE-RSA-AES128-CBC-SHA":               tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	"DHE-RSA-AES256-CBC-SHA":               tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	"RSA-AES128-CBC-SHA":                   tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"RSA-AES256-CBC-SHA":                   tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-RSA-3DES-EDE-CBC-SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"RSA-3DES-EDE-CBC-SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// List of supported cipher suites in descending order of preference.
// Ordering is very important! Getting the wrong order will break
// mainstream clients, especially with HTTP/2.
//
// Note that TLS_FALLBACK_SCSV is not in this list since it is always
// added manually.
var supportedCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// List of all the ciphers we want to use by default
var defaultCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
}

// isChaCha returns true if the cipher suite uses Salsa/ChaCha20 as cipher.
func isChaCha(suiteID uint16) bool {
	switch suiteID {
	case 0xcc13, 0xcc14, 0xcca8, 0xcca9, 0xccac:
		return true
	default:
		return false
	}
}

// PreferChaChaIfFirst moves Salsa/ChaCha20 cipher suites to the front.
func PreferChaChaIfFirst(clientHello *tls.ClientHelloInfo, ours []uint16) []uint16 {
	if !isChaCha(clientHello.CipherSuites[0]) {
		return nil
	}

	reordered := make([]uint16, 0, len(ours))
	// first pass: preferred ciphers
	for _, suiteID := range ours {
		if isChaCha(suiteID) {
			reordered = append(reordered, suiteID)
		}
	}
	// second pass: all remaining
	for _, suiteID := range ours {
		if !isChaCha(suiteID) {
			reordered = append(reordered, suiteID)
		}
	}

	return reordered
}
