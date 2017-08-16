const fs = require('fs');
const mkdirp = require('mkdirp');
const path = require('path');

/**
 * Middleware, providing functions for storing and retrieving
 * certificates and tokens.
 */
class WebRoot {
  /**
   * Constructs an {@link WebRoot} instance.
   * @param {!object} config Configuration options
   * @constructor
   */
  constructor(config) {
    this.config_ = config;
  }

  /**
   * Retrieves the challenge token for a specific domain.
   *
   * @method get
   * @param {!object} config Configuration options
   * @param {!string} domain The token domain
   * @param {!string} token The challenge token to be retrieved
   * @param {!Function} callback Callback function to call with the read token
   */
  get(config, domain, token, callback) {
    let tokenFile = path.join(
      config.webrootPath || this.config_.webrootPath,
      '.well-known',
      'acme-challenge',
      token
    );

    fs.readFile(tokenFile, 'utf8', callback);
  }

  /**
   * Returns the provided default configuration options.
   *
   * @method getOptions
   * @return {Object} Returns the default configuration options
   */
  getOptions() {
    return this.config_;
  }

  /**
   * Stores the challenge token for a specific domain.
   *
   * @method set
   * @param {!object} config Configuration options
   * @param {!string} domain The token domain
   * @param {!string} token The name of the file, where the challenge should be stored
   * @param {!string} secret The challenge token to be stored
   * @param {!Function} callback Callback function to call when token is stored
   */
  set(config, domain, token, secret, callback) {
    let challengePath = path.join(
      config.webrootPath || this.config_.webrootPath,
      '.well-known',
      'acme-challenge'
    );

    mkdirp(challengePath, (error) => {
      if (error) {
        callback(error);
      } else {
        let tokenFile = path.join(challengePath, token);

        fs.writeFile(tokenFile, secret, 'utf8', (error) => {
          if (error) {
            callback(error);
          } else {
            callback();
          }
        });
      }
    });
  }

  /**
   * Removes the challenge token for a specific domain.
   *
   * @method remove
   * @param {!object} config Configuration options
   * @param {!string} domain The token domain
   * @param {!string} token The token file to be removed
   * @param {!Function} callback Callback function to call when token is removed
   */
  remove(config, domain, token, callback) {
    let tokenFile = path.join(
      config.webrootPath || this.config_.webrootPath,
      '.well-known',
      'acme-challenge',
      token
    );

    fs.unlink(tokenFile, (error) => {
      if (error) {
        callback(error);
      } else {
        callback();
      }
    });
  }
}

module.exports = WebRoot;
