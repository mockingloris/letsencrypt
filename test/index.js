const LetsEncrypt = require('../src');
const assert = require('chai').assert;
const async = require('metal').async;
const sinon = require('sinon');

describe('LetsEncrypt', () => {
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
    assert.strictEqual(LetsEncrypt.defPrivateKeyPath, store.getOptions().domainKeyPath);
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

    LetsEncrypt.register(mockGreenlock, config)
      .then(thenFn);

    async.nextTick(() => {
      assert.isTrue(thenFn.calledWith(expectedResult));

      done();
    });
  });

  it('should register a certificate with renewal', (done) => {
    const config = {
      server: 'staging'
    };

    const expectedResult = 1;

    const mockResult = {
      _renewing: expectedResult
    };

    const mockGreenlock = {
      register: () => {
        return Promise.resolve(mockResult);
      }
    };

    const thenFn = sinon.spy();

    LetsEncrypt.register(mockGreenlock, config)
      .then(thenFn);

    async.nextTick(() => {
      assert.isTrue(thenFn.calledWith(expectedResult));

      done();
    });
  });

  it('should call `register` from `getCertificate` method', (done) => {
    let receivedGlInst;
    let receivedConfig;

    const expectedResult = {
      cert1: {}
    };

    const registerStub = sinon.stub(LetsEncrypt, 'register', (glInst, config) => {
      receivedGlInst = glInst;
      receivedConfig = config;

      return Promise.resolve(expectedResult);
    });

    const thenFn = sinon.spy();

    const config = {
      server: 'staging'
    };

    LetsEncrypt.getCertificate(config)
       .then(thenFn);

    async.nextTick(() => {
      registerStub.restore();

      assert.isTrue(thenFn.calledWith(expectedResult));
      assert.isObject(receivedGlInst);
      assert.isObject(receivedConfig);

      done();
    });
  });
});
