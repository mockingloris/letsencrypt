const WebRoot = require('./webroot');
const greenlock = require('greenlock');
const store = require('le-store-certbot');

const DAY = 24 * 60 * 60 * 1000;

/**
 * Registers and renews certificates on user's behalf.
 */
class LetsEncrypt {
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
  static getCertificate(config) {
    let store = LetsEncrypt.createStore(config);
    let glInst = LetsEncrypt.createGreenlockInstance(store, config);

    return LetsEncrypt.register(glInst, config);
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

module.exports = LetsEncrypt;
