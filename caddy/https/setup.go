package https

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/xenolf/lego/acme"
)

// Setup sets up the TLS configuration and installs certificates that
// are specified by the user in the config file. All the automatic HTTPS
// stuff comes later outside of this function.
func Setup(c *setup.Controller) (middleware.Middleware, error) {
	if c.Port == "80" || c.Scheme == "http" {
		c.TLS.Enabled = false
		log.Printf("[WARNING] TLS disabled for %s://%s.", c.Scheme, c.Address())
		return nil, nil
	}
	c.TLS.Enabled = true

	for c.Next() {
		var certificateFile, keyFile, loadDir, maxCerts string

		args := c.RemainingArgs()
		switch len(args) {
		case 1:
			c.TLS.LetsEncryptEmail = args[0]

			// user can force-disable managed TLS this way
			if c.TLS.LetsEncryptEmail == "off" {
				c.TLS.Enabled = false
				return nil, nil
			}
		case 2:
			certificateFile = args[0]
			keyFile = args[1]
			c.TLS.Manual = true
		}

		// Optional block with extra parameters
		var hadBlock bool
		for c.NextBlock() {
			hadBlock = true
			switch c.Val() {
			case "key_type":
				arg := c.RemainingArgs()
				value, ok := supportedKeyTypes[strings.ToUpper(arg[0])]
				if !ok {
					return nil, c.Errf("Wrong KeyType name or KeyType not supported '%s'", c.Val())
				}
				KeyType = value
			case "protocols":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.ArgErr()
				}
				value, ok := supportedProtocols[strings.ToLower(args[0])]
				if !ok {
					return nil, c.Errf("Wrong protocol name or protocol not supported '%s'", c.Val())
				}
				c.TLS.ProtocolMinVersion = value
				value, ok = supportedProtocols[strings.ToLower(args[1])]
				if !ok {
					return nil, c.Errf("Wrong protocol name or protocol not supported '%s'", c.Val())
				}
				c.TLS.ProtocolMaxVersion = value
			case "ciphers":
				for c.NextArg() {
					value, ok := supportedCiphersMap[strings.ToUpper(c.Val())]
					if !ok {
						return nil, c.Errf("Wrong cipher name or cipher not supported '%s'", c.Val())
					}
					c.TLS.Ciphers = append(c.TLS.Ciphers, value)
				}
			case "clients":
				clientCertList := c.RemainingArgs()
				if len(clientCertList) == 0 {
					return nil, c.ArgErr()
				}

				listStart, mustProvideCA := 1, true
				switch clientCertList[0] {
				case "request":
					c.TLS.ClientAuth = tls.RequestClientCert
					mustProvideCA = false
				case "require":
					c.TLS.ClientAuth = tls.RequireAnyClientCert
					mustProvideCA = false
				case "verify_if_given":
					c.TLS.ClientAuth = tls.VerifyClientCertIfGiven
				default:
					c.TLS.ClientAuth = tls.RequireAndVerifyClientCert
					listStart = 0
				}
				if mustProvideCA && len(clientCertList) <= listStart {
					return nil, c.ArgErr()
				}

				c.TLS.ClientCerts = clientCertList[listStart:]
			case "load":
				c.Args(&loadDir)
				c.TLS.Manual = true
			case "max_certs":
				c.Args(&maxCerts)
				c.TLS.OnDemand = true
			default:
				return nil, c.Errf("Unknown keyword '%s'", c.Val())
			}
		}

		// tls requires at least one argument if a block is not opened
		if len(args) == 0 && !hadBlock {
			return nil, c.ArgErr()
		}

		// set certificate limit if on-demand TLS is enabled
		if maxCerts != "" {
			maxCertsNum, err := strconv.Atoi(maxCerts)
			if err != nil || maxCertsNum < 1 {
				return nil, c.Err("max_certs must be a positive integer")
			}
			if onDemandMaxIssue == 0 || int32(maxCertsNum) < onDemandMaxIssue { // keep the minimum; TODO: We have to do this because it is global; should be per-server or per-vhost...
				onDemandMaxIssue = int32(maxCertsNum)
			}
		}

		// don't try to load certificates unless we're supposed to
		if !c.TLS.Enabled || !c.TLS.Manual {
			continue
		}

		// load a single certificate and key, if specified
		if certificateFile != "" && keyFile != "" {
			err := cacheUnmanagedCertificatePEMFile(certificateFile, keyFile)
			if err != nil {
				return nil, c.Errf("Unable to load certificate and key files for %s: %v", c.Host, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s and %s", certificateFile, keyFile)
		}

		// load a directory of certificates, if specified
		if loadDir != "" {
			err := loadCertsInDir(c, loadDir)
			if err != nil {
				return nil, err
			}
		}
	}

	setDefaultTLSParams(c.Config)

	return nil, nil
}

// loadCertsInDir loads all the certificates/keys in dir, as long as
// the file ends with .pem. This method of loading certificates is
// modeled after haproxy, which expects the certificate and key to
// be bundled into the same file:
// https://cbonte.github.io/haproxy-dconv/configuration-1.5.html#5.1-crt
//
// This function may write to the log as it walks the directory tree.
func loadCertsInDir(c *setup.Controller, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[WARNING] Unable to traverse into %s; skipping", path)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".pem") {
			certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
			var foundKey bool // use only the first key in the file

			bundle, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			for {
				// Decode next block so we can see what type it is
				var derBlock *pem.Block
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil {
					break
				}

				if derBlock.Type == "CERTIFICATE" {
					// Re-encode certificate as PEM, appending to certificate chain
					pem.Encode(certBuilder, derBlock)
				} else if derBlock.Type == "EC PARAMETERS" {
					// EC keys generated from openssl can be composed of two blocks:
					// parameters and key (parameter block should come first)
					if !foundKey {
						// Encode parameters
						pem.Encode(keyBuilder, derBlock)

						// Key must immediately follow
						derBlock, bundle = pem.Decode(bundle)
						if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
							return c.Errf("%s: expected elliptic private key to immediately follow EC parameters", path)
						}
						pem.Encode(keyBuilder, derBlock)
						foundKey = true
					}
				} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
					// RSA key
					if !foundKey {
						pem.Encode(keyBuilder, derBlock)
						foundKey = true
					}
				} else {
					return c.Errf("%s: unrecognized PEM block type: %s", path, derBlock.Type)
				}
			}

			certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
			if len(certPEMBytes) == 0 {
				return c.Errf("%s: failed to parse PEM data", path)
			}
			if len(keyPEMBytes) == 0 {
				return c.Errf("%s: no private key block found", path)
			}

			err = cacheUnmanagedCertificatePEMBytes(certPEMBytes, keyPEMBytes)
			if err != nil {
				return c.Errf("%s: failed to load cert and key for %s: %v", path, c.Host, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s", path)
		}
		return nil
	})
}

// Map of supported key types
var supportedKeyTypes = map[string]acme.KeyType{
	"P384":    acme.EC384,
	"P256":    acme.EC256,
	"RSA8192": acme.RSA8192,
	"RSA4096": acme.RSA4096,
	"RSA2048": acme.RSA2048,
}
