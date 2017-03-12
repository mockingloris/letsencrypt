/* eslint-disable no-invalid-this */
const WebRoot = require('../src/webroot');
const assert = require('chai').assert;
const crypto = require('crypto');
const del = require('del');
const fs = require('fs');
const mkdirp = require('mkdirp');
const path = require('path');

describe('WebRoot', () => {
  beforeEach((done) => {
    this.tmpDir_ = '.' + crypto.randomBytes(10).toString('hex');

    mkdirp(this.tmpDir_, (error) => {
      if (error) {
        throw new Error(error);
      }

      done();
    });
  });

  afterEach((done) => {
    del([this.tmpDir_]).then(() => done());
  });

  it('should return the passed default options', () => {
    const config = {
      bar: 'bar',
      foo: 'foo'
    };

    const webRoot = new WebRoot(config);

    assert.deepEqual(config, webRoot.getOptions());
  });

  it('should retrieve a token from the webroot path', (done) => {
    const challengePath = path.join(this.tmpDir_, '.well-known', 'acme-challenge');
    mkdirp(challengePath, (error) => {
      if (error) {
        throw new Error(error);
      }

      const webRoot = new WebRoot(null);
      const token = crypto.createHash('sha256').digest('hex');

      fs.writeFileSync(path.join(challengePath, token), token);

      const config = {
        webrootPath: this.tmpDir_
      };

      webRoot.get(config, 'foo', token, (error, readToken) => {
        assert.strictEqual(readToken, token);
        done();
      });
    });
  });

  it('should retrieve a token from the default webroot path', (done) => {
    const config = {
      webrootPath: this.tmpDir_
    };

    const challengePath = path.join(this.tmpDir_, '.well-known', 'acme-challenge');
    mkdirp(challengePath, (error) => {
      if (error) {
        throw new Error(error);
      }

      const webRoot = new WebRoot(config);
      const token = crypto.createHash('sha256').digest('hex');

      fs.writeFileSync(path.join(challengePath, token), token);

      webRoot.get({}, 'foo', token, (error, readToken) => {
        assert.strictEqual(readToken, token);
        done();
      });
    });
  });

  it('should store a token to the webroot path', (done) => {
    const challengePath = path.join(this.tmpDir_, '.well-known', 'acme-challenge');
    mkdirp(challengePath, (error) => {
      if (error) {
        throw new Error(error);
      }

      const webRoot = new WebRoot(null);
      const token = crypto.createHash('sha256').digest('hex');

      const config = {
        webrootPath: this.tmpDir_
      };

      webRoot.set(config, 'foo', token, token, (error) => {
        assert.isUndefined(error);
        done();
      });
    });
  });

  it('should store a token to the default webroot path', (done) => {
    const challengePath = path.join(this.tmpDir_, '.well-known', 'acme-challenge');
    mkdirp(challengePath, (error) => {
      if (error) {
        throw new Error(error);
      }

      const config = {
        webrootPath: this.tmpDir_
      };

      const webRoot = new WebRoot(config);
      const token = crypto.createHash('sha256').digest('hex');

      webRoot.set({}, 'foo', token, token, (error) => {
        assert.isUndefined(error);
        done();
      });
    });
  });

  it('should remove a token from the webroot path', (done) => {
    const challengePath = path.join(this.tmpDir_, '.well-known', 'acme-challenge');
    mkdirp(challengePath, (error) => {
      if (error) {
        throw new Error(error);
      }

      const webRoot = new WebRoot(null);
      const token = crypto.createHash('sha256').digest('hex');

      fs.writeFileSync(path.join(challengePath, token), token);

      const config = {
        webrootPath: this.tmpDir_
      };

      webRoot.remove(config, 'foo', token, (error) => {
        assert.isUndefined(error);
        done();
      });
    });
  });

  it('should remove a token from the default webroot path', (done) => {
    const config = {
      webrootPath: this.tmpDir_
    };

    const challengePath = path.join(this.tmpDir_, '.well-known', 'acme-challenge');
    mkdirp(challengePath, (error) => {
      if (error) {
        throw new Error(error);
      }

      const webRoot = new WebRoot(config);
      const token = crypto.createHash('sha256').digest('hex');

      fs.writeFileSync(path.join(challengePath, token), token);

      webRoot.remove({}, 'foo', token, (error) => {
        assert.isUndefined(error);
        done();
      });
    });
  });
});
