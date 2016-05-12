// +build alttls

package https

import (
	"crypto/tls"
	"math/big"

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

	// DHE needs this. Not used with ECDHE.
	c.TLS.DHPrime, c.TLS.DHGenerator, c.TLS.DHSubgroup = defaultDHPrime, defaultDHGenerator, defaultDHSubgroup

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

// Defaults for Diffie-Hellman key agreement.
//
// If you set |defaultDHSubgroup| to nil then the generator is expected to be 2 or 5
// (which is not enforced!) and our private key will be under |defaultDHPrime| instead
// of under |defaultDHSubgroup|. The latter is the default.
var (
	defaultDHPrime     *big.Int = nil
	defaultDHGenerator *big.Int = nil
	defaultDHSubgroup  *big.Int = nil
)

func init() {
	// The first values will be sent to any client if DHE is negotiated.
	// 3072-bit group with a 256-bit subgroup.
	defaultDHPrime, _ = new(big.Int).SetString("00ecbe75f9eed3a4be48b45fc71fa0ef2c944c67d1dfe851ee588c14711e7358386f6eeda1bd006f1e3746c9a2c4c2094931627b8757dc821b52c5a9f8e4e8b291b9bce20718338c8b8127137c54d3baa08209a3bc967d4f2f0ea60bc0cc8a5aa5e4deea1953b539cd22359183bbe17b462844ccd81a6e1a82c0f184a1bdabfb1d01201a7e272dc01190713d80b7688b55cf38af8cd3cfbfb131e7d5396c6b552af69c76ebe9465d7a32e037f0501eaa6c76fd7b3dcbdb9423ab4160e7a8b6b8a2f953f58a63293eec55406f3274b12600cc1c598509189c601226520ae24472c3770b2f37cc7beaa788e54f9c73e48f238d098ac1be5114d7cad53fbfdb97c1532539aeac5c2141b880b74dbfd2d0ce05c602e35de14e40f638632f712c6686c886078c4af4f7fa70ab9c6e5e6ea7d8c4fa20f58558e42bc5526e2dce5c79d3e52f98400f794d7a56fdf2f3a3522c651f08524557044f9e00f85a11526ecf737d04bbac52160d531ca53a5f2fab3334d702ab147c666219d7190772995d095393", 16)
	defaultDHGenerator, _ = new(big.Int).SetString("0bf26cc47169cbda5b3308cb1ab210b6d27d6f07013a6a2706fad66922abc335ae1c942150595b42895bcc1413050a2a2e266dda084d7b2d202e7772aea0db0731598a3f80898b8b13e4555468028d38b229fe2424b1c9b31437668fc7991fd9802c013776802ff22ac5f56fea04ce54b264285cf38a7bbe9ed91f52c6a251b021f8577f31e132479cb7ab17a13a2ec3c9012a9ed6493b71a8f3cff0041d39590916d48f4793d175951cbcce322efbc2b53e64ca6f843c0f4f49d98387cadf5be0c37feda5f553f39a9d0183e0e25d8c912d81bcb49c5edae0e53a6525b193c789243e51608dd03da0bd28203de1d37a07c1d2d8750335cd8acb05f89c52ef6211f5ecb16c2911e1d88bff6ba704e3ba7f0a1a860df1d591e0dc7a038b034b4d32e34754b5828d38be282ab0dbc71c289d99e7d84a56b7fccc8eec6488008d66636ec8f3b4c88a9476e40cc21739ecf9081e11fc10bccd44aaa40c5c8eef42e7506bac7fe5aa7d086f97dbfd272ae1a5160a8a4b995c813f56fcf560feb62f7f", 16)
	defaultDHSubgroup, _ = new(big.Int).SetString("f694a098f5f799fd57e2002eed71f97afc9ac4f3d5e063320989a21d480a518b", 16)
}
