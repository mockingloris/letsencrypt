const LetsEncrypt = require('../src');
const assert = require('chai').assert;
const async = require('metal').async;
const crypto = require('crypto');
const del = require('del');
const fs = require('fs');
const mkdirp = require('mkdirp');
const path = require('path');
const sinon = require('sinon');

/* eslint-disable no-invalid-this */
describe('LetsEncrypt', () => {
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

  it('should create a challenge, passing configuration options', () => {
    const challenge = LetsEncrypt.createChallenge({
      webrootPath: 'foo'
    });

    assert.isObject(challenge);
    assert.isFunction(challenge.getOptions);
    assert.strictEqual('foo', challenge.getOptions().webrootPath);
  });

  it('should create a store, passing configuration options', () => {
    const config = {
      configDir: 'foo/config',
      domainKeyPath: 'foo/domainKeyPath'
    };

    const store = LetsEncrypt.createStore(config);

    assert.isObject(store);
    assert.isFunction(store.getOptions);
    assert.isObject(store.accounts);
    assert.isObject(store.certificates);
    assert.isObject(store.configs);
    assert.isObject(store.keypairs);
    assert.strictEqual('foo/domainKeyPath', store.getOptions().domainKeyPath);
  });

  it('should create a store with default private key path', () => {
    const config = {
      configDir: 'foo/config'
    };

    const store = LetsEncrypt.createStore(config);

    assert.isObject(store);
    assert.isFunction(store.getOptions);
    assert.isObject(store.accounts);
    assert.isObject(store.certificates);
    assert.isObject(store.configs);
    assert.isObject(store.keypairs);
    assert.strictEqual(
      LetsEncrypt.defPrivateKeyPath,
      store.getOptions().domainKeyPath
    );
  });

  it('should create a Greenlock instance, passing configuration options', () => {
    const config = {
      server: 'staging'
    };

    const store = LetsEncrypt.createStore(config);

    const glInstance = LetsEncrypt.createGreenlockInstance(store, config);

    assert.isObject(glInstance);
    assert.isFunction(glInstance.register);
  });

  it('should register a certificate', (done) => {
    const config = {
      server: 'staging'
    };

    const expectedResult = {
      cert1: {}
    };

    const mockGreenlock = {
      register: () => {
        return Promise.resolve(expectedResult);
      }
    };

    const thenFn = sinon.spy();

    LetsEncrypt.register(mockGreenlock, config).then(thenFn);

    async.nextTick(() => {
      assert.isTrue(thenFn.calledWith(expectedResult));

      done();
    });
  });

  it('should return certificate via `generateCertificate` method', (done) => {
    let receivedGlInst;
    let receivedConfig;

    const expectedResult = {
      cert: {}
    };

    const registerStub = sinon.stub(
      LetsEncrypt,
      'register',
      (glInst, config) => {
        receivedGlInst = glInst;
        receivedConfig = config;

        return Promise.resolve(expectedResult);
      }
    );

    const concatenateFn = sinon.spy((config) => {
      return Promise.resolve({
        data: 'foo'
      });
    });

    const concatenateStub = sinon.stub(
      LetsEncrypt,
      'concatenateKeyAndFullchain',
      concatenateFn
    );

    const thenFn = sinon.spy();

    const config = {
      server: 'staging'
    };

    LetsEncrypt.generateCertificate(config).then(thenFn);

    async.nextTick(() => {
      concatenateStub.restore();
      registerStub.restore();

      assert.isTrue(thenFn.calledWith(expectedResult));
      assert.isTrue(concatenateFn.calledOnce);
      assert.isObject(receivedGlInst);
      assert.isObject(receivedConfig);

      done();
    });
  });

  it('should renew certificate via `renewCertificate` method', (done) => {
    let receivedGlInst;
    let receivedConfig;

    const expectedResult = {
      cert: {}
    };

    const renewStub = sinon.stub(LetsEncrypt, 'renew', (glInst, config) => {
      receivedGlInst = glInst;
      receivedConfig = config;

      return Promise.resolve(expectedResult);
    });

    const concatenateFn = sinon.spy((config) => {
      return Promise.resolve({
        data: 'foo'
      });
    });

    const concatenateStub = sinon.stub(
      LetsEncrypt,
      'concatenateKeyAndFullchain',
      concatenateFn
    );

    const thenFn = sinon.spy();

    const config = {
      renewWithin: 8,
      server: 'staging'
    };

    LetsEncrypt.renewCertificate(config).then(thenFn);

    async.nextTick(() => {
      concatenateStub.restore();
      renewStub.restore();

      assert.isObject(receivedConfig);
      assert.isObject(receivedGlInst);
      assert.isTrue(concatenateFn.calledOnce);
      assert.isTrue(thenFn.calledWith(expectedResult));
      assert.strictEqual(receivedConfig.renewWithin, 691200000); // 8 days in milliseconds

      done();
    });
  });

  it('should throw error with E_NOT_RENEWABLE code when certificate is not renewable', (done) => {
    let receivedGlInst;
    let receivedConfig;

    let error = new Error();
    error.code = 'E_NOT_RENEWABLE';

    const renewStub = sinon.stub(LetsEncrypt, 'renew', (glInst, config) => {
      receivedGlInst = glInst;
      receivedConfig = config;

      return Promise.reject(error);
    });

    const catchFn = sinon.spy();

    const config = {
      server: 'staging'
    };

    LetsEncrypt.renewCertificate(config).catch(catchFn);

    async.nextTick(() => {
      renewStub.restore();

      assert.isTrue(catchFn.calledWith(error));
      assert.strictEqual(error.code, 'E_NOT_RENEWABLE');
      assert.isObject(receivedGlInst);
      assert.isObject(receivedConfig);

      done();
    });
  });

  it('should concatenate private key and fullchain', (done) => {
    fs.writeFileSync(path.join(this.tmpDir_, 'foo.pem'), 'foo');
    fs.writeFileSync(path.join(this.tmpDir_, 'fullchain.pem'), 'bar');

    LetsEncrypt.concatenateKeyAndFullchain({
      configDir: this.tmpDir_,
      domains: ['foo.com'],
      domainKeyPath: path.join(this.tmpDir_, 'foo.pem'),
      fullchainPath: path.join(this.tmpDir_, 'fullchain.pem'),
      keyFullchainPath: path.join(
        this.tmpDir_,
        ':hostname',
        'keyfullchain.pem'
      )
    }).then((buffer) => {
      let data = buffer.toString('utf8');

      assert.strictEqual('foo' + 'bar', data);
      done();
    });
  });
});
