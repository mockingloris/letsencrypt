<h1 align="center">WeDeploy LetsEncrypt</h1>

<h5 align="center">Simple Node.js library and CLI to manage Let's Encrypt certificates</h5>

<div align="center">
  <a href="http://travis-ci.com/wedeploy/letsencrypt">
    <img src="https://travis-ci.org/wedeploy/letsencrypt.svg?branch=master" alt="Travis CI" />
  </a>
</div>

## Install

```sh
$ npm i --save wedeploy-letsencrypt
```

If you prefer to install it globally and use the CLI, use the following command:

```sh
$ npm i -g wedeploy-letsencrypt
```

Then, the command `wel` should be available in PATH. Run `wel --help` for more information about the available options.

## Usage

### Using as CLI

```
$ wel <cmd> [args]

Commands:
  certonly  Issue/renew certificate(s)

Options:
  --account-key-path  Path to privkey.pem to use for account (default: generate new)                            [string]
  --agree-tos         Agree to the Let's Encrypt Subscriber Agreement.                                        [required]
  --cert-path         Path to where new cert.pem is saved.      [string] [default: ":configDir/live/:hostname/cert.pem"]
  --chain-path        Path to where new chain.pem is saved.    [string] [default: ":configDir/live/:hostname/chain.pem"]
  --config-dir        Configuration directory.                                  [string] [default: "~/letsencrypt/etc/"]
  --debug             Show traces and logs.                                                   [boolean] [default: false]
  --domains           Domain names to apply. For multiple domains use space separated list of domains as a parameter.
                                                                                                      [array] [required]
  --domain-key-path   Path to privkey.pem to use for domain (default: generate new)                             [string]
  --duplicate         Allow getting a certificate that duplicates an existing one/is an early renewal.
                                                                                              [boolean] [default: false]
  --email             Email used for registration and recovery contact.                              [string] [required]
  --fullchain-path    Path to where new cert.pem is saved.      [string] [default: ":configDir/live/:hostname/cert.pem"]
  --http-01-port      Use HTTP-01 challenge type with this port.                                  [number] [default: 80]
  --renew-within      Renew certificates this many days before expiry.                             [number] [default: 7]
  --rsa-key-size      Size (in bits) of the RSA key.                                            [number] [default: 2048]
  --server            ACME Directory Resource URI. Default: staging server. Use "production" to connect to the
                      production server.        [string] [choices: "https://acme-staging.api.letsencrypt.org/directory",
                         "https://acme-v01.api.letsencrypt.org/directory", "staging", "production"] [default: "staging"]
  --webroot-path      public_html / webroot path.                                 [string] [default: "/var/lib/haproxy"]
  --help              Show help                                                                                [boolean]
```

To issue a certificate for a domain, you may use the following command:
```
$ wel certonly --agree-tos --domains example.com www.example.com --email admin@mycompany.com --config-dir ~/cfg-dir --server staging --webroot-path /var/lib/haproxy
```

The command will validate the domain `example.com` using HTTP challenge and register or renew a certificate for it. The server (HAProxy for example) should be able to serve files from `/var/lib/haproxy` directory.

### Using as API

In an application, require WeDeploy Let's Encrypt implementation and call `getCertificate` method, passing configuration options as properties of an object. The function returns a `Promise`, which will be fulfilled with the registered certificates. The certificates will be stored to the configuration directory (`configDir` property) already.
The list of available options are the same as those, which could be specified from the command line, but in camelCase. For example, `agree-tos` should become `agreeTos` and `rsa-key-size` should become `rsaKeySize`.

Example code:

```js
const LetsEncrypt = require('wedeploy-letsencrypt');

LetsEncrypt.getCertificate(options)
  .then((certs) => {
    console.log('Got certificate(s) for', certs.altnames.join(', '));
  })
  .catch((error) => {
    console.error(error);
  });
```

## Test

```sh
$ npm test
```

## License

[BSD License](https://github.com/wedeploy/letsencrypt/blob/master/LICENSE.md) © Liferay, Inc.