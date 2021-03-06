const WebRoot = require('./webroot');
const fs = require('fs');
const greenlock = require('greenlock');
const homedir = require('homedir')();
const mkdirp = require('mkdirp');
const path = require('path');
const store = require('le-store-certbot');

const DAY = 24 * 60 * 60 * 1000;

/**
 * Registers and renews certificates on user's behalf.
 */
class LetsEncrypt {
  /**
   * Concatenates the private key and fullchain in one file.
   * @param {!object} config Configuration options
   * @return {Promise} Promise, which will be resolved with the
   *  concatenated private key and full certificate chain as buffer
   */
  static async concatenateKeyAndFullchain(config) {
    return new Promise((resolve, reject) => {
      const normalizeOptions = {
        configDir: config.configDir,
        hostname: config.domains[0]
      };

      let privateKeyPath =
        config.domainKeyPath || LetsEncrypt.defPrivateKeyPath;

      privateKeyPath = normalizePath(privateKeyPath, normalizeOptions);

      let fullchainPath = normalizePath(config.fullchainPath, normalizeOptions);
      let keyFullchainPath = normalizePath(
        config.keyFullchainPath,
        normalizeOptions
      );

      return Promise.all([readFile(privateKeyPath), readFile(fullchainPath)])
        .then((privateKeyData, fullchainData) => {
          const keyFullchainData = Buffer.concat(privateKeyData, fullchainData);

          return writeFile(
            keyFullchainPath,
            keyFullchainData
          ).then((keyFullchainData) => {
            resolve(keyFullchainData);
          });
        })
        .catch((error) => {
          reject(error);
        });
    });
  }

  /**
   * Creates challenge for domain(s) confirmation.
   *
   * @static
   * @method createChallenge
   * @param {!object} config Configuration options
   * @return {object} Challenge middleware
   */
  static createChallenge(config) {
    let leChallenge = new WebRoot({
      webrootPath: config.webrootPath
    });

    return leChallenge;
  }

  /**
   * Creates a Greenlock instance passing configuration options.
   *
   * @static
   * @method createGreenlockInstance
   * @param {!object} store Storage for storing and retrieving tokens
   * @param {!object} config Configuration options
   * @return {object} Greenlock instance
   */
  static createGreenlockInstance(store, config) {
    let leChallenge = LetsEncrypt.createChallenge(config);

    let leChallenges = {
      'http-01': leChallenge
    };

    let gl = greenlock.create({
      challenges: leChallenges,
      debug: config.debug,
      duplicate: config.duplicate,
      renewWithin: config.renewWithin * DAY,
      server: config.server,
      store: store
    });

    return gl;
  }

  /**
   * Creates a store for saving certificates and key pairs.
   *
   * @static
   * @method createStore
   * @param {!object} config Configuration options
   * @return {object} Storage middleware
   */
  static createStore(config) {
    let privateKeyPath = config.domainKeyPath || LetsEncrypt.defPrivateKeyPath;

    let leStore = store.create({
      configDir: config.configDir,
      privkeyPath: privateKeyPath,
      fullchainPath: config.fullchainPath,
      certPath: config.certPath,
      chainPath: config.chainPath,
      webrootPath: config.webrootPath,
      domainKeyPath: config.domainKeyPath,
      accountKeyPath: config.accountKeyPath
    });

    return leStore;
  }

  /**
   * Retrieves certificate for specific domain(s).
   *
   * @static
   * @method generateCertificate
   * @param {!object} config Configuration options
   * @return {Promise} Returns Promise, which will be fulfilled once the
   *   certificates for the specified domain(s) are issued or renewed,
   *   if renewing process was requested
   */
  static async generateCertificate(config) {
    config.domainKeyPath =
      config.domainKeyPath || LetsEncrypt.defPrivateKeyPath;
    config.server = normalizeServerUrl(config.server);

    let store = LetsEncrypt.createStore(config);
    let glInst = LetsEncrypt.createGreenlockInstance(store, config);

    const certs = await LetsEncrypt.register(glInst, config);
    await LetsEncrypt.concatenateKeyAndFullchain(config);

    return certs;
  }

  /**
   * Renews the certificate for specific domain(s). If the certificate was not
   * renewable, an exception will be thrown with a property `code` which value
   * will be `E_NOT_RENEWABLE`.
   *
   * @param {object} config Configuration options
   * @return {Promise} Returns Promise, which will be fulfilled once the
   *   certificates for the specified domain(s) renewed,
   *   if renewing process was requested
   */
  static async renewCertificate(config) {
    config.domainKeyPath =
      config.domainKeyPath || LetsEncrypt.defPrivateKeyPath;
    config.server = normalizeServerUrl(config.server);
    config.renewWithin =
      (config.renewWithin || LetsEncrypt.defaultOptions.renewWithin) * DAY;

    let store = LetsEncrypt.createStore(config);
    let glInst = LetsEncrypt.createGreenlockInstance(store, config);

    const certs = await LetsEncrypt.renew(glInst, config);
    await LetsEncrypt.concatenateKeyAndFullchain(config);

    return certs;
  }

  /**
   * Reads file content as buffer.
   * @param {!string} filePath Path to the file to be read
   * @return {Promise} Promise, which will be resolved with
   *   file content read as buffer
   */
  readFile(filePath) {
    return new Promise((resolve, reject) => {
      fs.readFile(filePath, (error, data) => {
        if (error) {
          reject(error);
        } else {
          resolve(data);
        }
      });
    });
  }

  /**
   * Registers a certificate for the provided domain.
   *
   * @static
   * @method register
   * @param {!object} gl Greenlock instance
   * @param {!object} config Object, providing configuration params for Greenlock
   * @return {Promise} Returns Promise, which will be fulfilled once the
   *   certificates for the specified domain(s) are issued and renewed,
   *   if renewing process was requested
   */
  static async register(gl, config) {
    return gl
      .register({
        agreeTos: config.agreeTos,
        challengeType: 'http-01',
        debug: config.debug,
        domains: config.domains,
        email: config.email,
        rsaKeySize: config.rsaKeySize
      })
      .then((certs) => {
        return certs;
      });
  }

  /**
   * Renews a certificate for the provided domain.
   *
   * @static
   * @method renew
   * @param {!object} gl Greenlock instance
   * @param {!object} config Object, providing configuration params for Greenlock
   * @return {Promise} Returns Promise, which will be fulfilled once the
   *   certificates for the specified domain(s) are renewed
   */
  static async renew(gl, config) {
    const existingCertificates = await gl.check(config);

    if (!existingCertificates) {
      throw new Error(
        `No certificate for the domains '${config.domains}' found, aborting ` +
          'renewal attempt.'
      );
    }

    const certs = await gl.renew(config, existingCertificates);

    return certs;
  }
}

/**
 * Provides the default configuration options.
 *
 * @static
 */
LetsEncrypt.defaultOptions = {
  agreeTos: true,
  certPath: ':configDir/live/:hostname/cert.pem',
  chainPath: ':configDir/live/:hostname/chain.pem',
  configDir: '~/letsencrypt/etc/',
  debug: false,
  duplicate: false,
  fullchainPath: ':configDir/live/:hostname/fullchain.pem',
  http01Port: 80,
  keyFullchainPath: ':configDir/live/:hostname/keyfullchain.pem',
  renewWithin: 7,
  rsaKeySize: 2048,
  server: 'staging',
  webrootPath: '/var/lib/haproxy'
};

/**
 * Provides the default private key path.
 *
 * @static
 */
LetsEncrypt.defPrivateKeyPath = ':configDir/live/:hostname/privkey.pem';

/**
 * Replaces default
 * @param {!string} path The path to be normalized
 * @param {!{configDir:string,hostname:string}} config Configuration options
 * @return {string} Normalized path
 */
function normalizePath(path, config) {
  path = path
    .replace(/^~/, homedir)
    .replace(/:configDir/g, config.configDir)
    .replace(/:hostname/g, config.hostname);

  return path;
}

/**
 * Normalizes the provider ACME server Url. If `staging` or `production` are
 * passed, they will be replaced with the real staging or production Url.
 * Otherwise, the param will be left untouched.
 * @param {!string} url The ACME server url
 * @return {string} The real staging or production Url
 */
function normalizeServerUrl(url) {
  let normalizedUrl = url;

  if (url === 'staging') {
    normalizedUrl = greenlock.stagingServerUrl;
  } else if (url === 'production') {
    normalizedUrl = greenlock.productionServerUrl;
  }

  return normalizedUrl;
}

/**
 * Reads file content as buffer.
 * @param {!string} filePath Path to the file to be read
 * @return {Promise} Promise, which will be resolved with
 *   file content read as buffer
 */
function readFile(filePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, (error, data) => {
      if (error) {
        reject(error);
      } else {
        resolve(data);
      }
    });
  });
}

/**
 * Writes file content as buffer.
 * @param {!string} filePath Path to the file to be written
 * @param {Buffer} data Data to be written
 * @return {Promise} Promise, which will be resolved with
 *   file content written as buffer
 */
function writeFile(filePath, data) {
  return new Promise((resolve, reject) => {
    mkdirp(path.dirname(filePath), (error) => {
      if (error) {
        reject(error);
      } else {
        fs.writeFile(filePath, data, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve(data);
          }
        });
      }
    });
  });
}

module.exports = LetsEncrypt;
