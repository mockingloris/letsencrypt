#!/usr/bin/env node

/* eslint-disable no-console */
const greenlock = require('greenlock');
const homedir = require('homedir')();
const mkdirp = require('mkdirp');
const pkg = require('../package.json');
const yargs = require('yargs');

let LetsEncrypt = require('../src');

let argv = yargs.usage('$0 <cmd> [args]')
  .command('certonly', 'Issue/renew certificate(s)')
  .options({
    'account-key-path': {
      describe: 'Path to privkey.pem to use for account (default: generate new)',
      type: 'string'
    },
    'agree-tos': {
      demandOption: true,
      describe: 'Agree to the Let\'s Encrypt Subscriber Agreement.'
    },
    'cert-path': {
      default: ':configDir/live/:hostname/cert.pem',
      describe: 'Path to where new cert.pem is saved.',
      type: 'string'
    },
    'chain-path': {
      default: ':configDir/live/:hostname/chain.pem',
      describe: 'Path to where new chain.pem is saved.',
      type: 'string'
    },
    'config-dir': {
      default: '~/letsencrypt/etc/',
      describe: 'Configuration directory.',
      type: 'string'
    },
    'debug': {
      default: false,
      describe: 'Show traces and logs.',
      type: 'boolean'
    },
    'domains': {
      demandOption: true,
      describe: 'Domain names to apply. For multiple domains use space separated list of domains as a parameter.',
      type: 'array'
    },
    'domain-key-path': {
      describe: 'Path to privkey.pem to use for domain (default: generate new)',
      type: 'string'
    },
    'duplicate': {
      default: false,
      describe: 'Allow getting a certificate that duplicates an existing one/is an early renewal.',
      type: 'boolean'
    },
    'email': {
      demandOption: true,
      describe: 'Email used for registration and recovery contact.',
      type: 'string'
    },
    'fullchain-path': {
      default: ':configDir/live/:hostname/fullchain.pem',
      describe: 'Path to where new fullchain.pem (cert + chain) is saved.',
      type: 'string'
    },
    'http-01-port': {
      coerce: (arg) => {
        if (arg <= 0 || !isFinite(arg)) {
          throw new Error('Invalid HTTP port option.');
        }

        return arg;
      },
      default: 80,
      describe: 'Use HTTP-01 challenge type with this port.',
      type: 'number'
    },
    'key-fullchain-path': {
      default: ':configDir/live/:hostname/keyfullchain.pem',
      describe: 'Path to where key + fullchain.pem is saved.',
      type: 'string'
    },
    'renew-within': {
      coerce: (arg) => {
        if (arg <= 0 || !isFinite(arg)) {
          throw new Error('Invalid renew days option. Must be greater than 0.');
        }

        return arg;
      },
      default: 7,
      describe: 'Renew certificates this many days before expiry.',
      type: 'number'
    },
    'rsa-key-size': {
      coerce: (arg) => {
        if (arg < 2048 || !isFinite(arg)) {
          throw new Error('Invalid RSA key size option. Must be 2048 or greater.');
        }

        return arg;
      },
      default: 2048,
      describe: 'Size (in bits) of the RSA key.',
      type: 'number'
    },
    'server': {
      default: 'staging',
      describe: 'ACME Directory Resource URI. Default: staging server. ' +
        'Use "production" to connect to the production server.',
      choices: [greenlock.stagingServerUrl, greenlock.productionServerUrl, 'staging', 'production'],
      type: 'string'
    },
    'webroot-path': {
      default: '/var/lib/haproxy',
      describe: 'public_html / webroot path.',
      type: 'string'
    }
  })
  .demandCommand(1, 'Error: no command specified. You need to specify at least one command.')
  .wrap(120)
  .strict()
  .alias('v', 'version')
  .version(() => {
    return pkg.version;
  })
  .help()
  .argv;

let options = {};

Object.keys(argv).forEach((key) => {
  let val = argv[key];

  if (typeof val === 'string') {
    val = val.replace(/^~/, homedir);
  }

  key = key.replace(/\-([a-z0-9])/ig, (c) => {
    return c[1].toUpperCase();
  });

  options[key] = val;
});

Object.keys(argv).forEach((key) => {
  let val = argv[key];

  if (typeof val === 'string') {
    val = val.replace(/(\:configDir)|(\:config)/, options.configDir);
  }

  options[key] = val;
});

mkdirp(options.configDir, (error) => {
  if (error) {
    console.error('Could not create --config-dir "' + options.configDir + '"', error.code);
  } else {
    main();
  }
});

/**
 * Entry point. Registers or renews a certificate for a given domain.
 */
function main() {
  LetsEncrypt.getCertificate(options)
    .then((certs) => {
      let privateKeyPath = options.domainKeyPath || LetsEncrypt.defPrivateKeyPath;

      console.log('Got certificate(s) for', certs.altnames.join(', '));
      console.log('\tIssued at' + new Date(certs.issuedAt).toISOString());
      console.log('\tValid until', new Date(certs.expiresAt).toISOString());
      console.log('Private key installed at:');
      console.log(
        privateKeyPath
        .replace(/:configDir/g, options.configDir)
        .replace(/:hostname/g, options.domains[0])
      );

      console.log('Certificates installed at:');
      console.log([
          options.certPath,
          options.chainPath,
          options.fullchainPath,
          options.keyFullchainPath
        ].join('\n')
        .replace(/:configDir/g, options.configDir)
        .replace(/:hostname/g, options.domains[0])
      );
    })
    .catch((error) => {
      console.error(error);
    });
}
