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

      let privateKeyPath = config.domainKeyPath || LetsEncrypt.defPrivateKeyPath;

      privateKeyPath = normalizePath(privateKeyPath, normalizeOptions);

      let fullchainPath = normalizePath(config.fullchainPath, normalizeOptions);
      let keyFullchainPath = normalizePath(config.keyFullchainPath, normalizeOptions);

      return Promise.all([readFile(privateKeyPath), readFile(fullchainPath)])
        .then((privateKeyData, fullchainData) => {
          const keyFullchainData = Buffer.concat(privateKeyData, fullchainData);

          return writeFile(keyFullchainPath, keyFullchainData)
            .then((keyFullchainData) => {
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
   * @method getCertificate
   * @param {!object} config Configuration options
   * @return {Promise} Returns Promise, which will be fulfilled once the
   *   certificates for the specified domain(s) are issued and renewed,
   *   if renewing process was requested
   */
  static async getCertificate(config) {
    let store = LetsEncrypt.createStore(config);
    let glInst = LetsEncrypt.createGreenlockInstance(store, config);

    let certs = await LetsEncrypt.register(glInst, config);
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
  static register(gl, config) {
    return gl.register({
      agreeTos: config.agreeTos,
      challengeType: 'http-01',
      debug: config.debug,
      domains: config.domains,
      email: config.email,
      rsaKeySize: config.rsaKeySize
    }).then((certs) => {
      if (!certs._renewing) {
        return certs;
      } else {
        return certs._renewing;
      }
    });
  }
}

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
