var Key = require('../');
var sha256 = require('core-hash').sha256;

var valid = require('./fixtures/valid.json');
var invalid = require('./fixtures/invalid.json');

describe('key', function () {
  describe('from private key (valid sigs)', function () {
    valid.forEach(function (fixture) {
      var key = new Key({ private: new Buffer(fixture.prv, 'hex') });

      it('generate public keys for ' + fixture.prv, function () {
        expect(key.public.toString('hex')).to.equal(fixture.pub);
        key.compressed = false;
        expect(key.public.toString('hex')).to.equal(fixture.pubUncompressed);
      });

      if (fixture.signatures) {
        fixture.signatures.forEach(function (signature, i) {
          var hash = sha256(signature.data);

          it('generate correct k #' + i + ' for ' + fixture.prv, function () {
            expect(Key.generateK(new Buffer(fixture.prv, 'hex'), hash).toString('hex')).to.equal(signature.k);
          });

          it('generate correct signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.sign(hash).toString('hex')).to.equal(signature.sig);
          });

          it('verify signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.verify(hash, new Buffer(signature.sig, 'hex'))).to.be.true;
          });
        });
      }
    });
  });

  describe('from private key (invalid sigs)', function () {
    invalid.forEach(function (fixture) {
      var key = new Key({ private: new Buffer(fixture.prv, 'hex') });

      if (fixture.signatures) {
        fixture.signatures.forEach(function (signature, i) {
          var hash = sha256(signature.data);

          if (signature.change === 'data') {
            it('generate incorrect k #' + i + ' for ' + fixture.prv, function () {
              expect(Key.generateK(new Buffer(fixture.prv, 'hex'), hash).toString('hex')).to.not.equal(signature.k);
            });
          }

          it('generate incorrect signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.sign(hash).toString('hex')).to.not.equal(signature.sig);
          });

          it('not verify signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.verify(hash, new Buffer(signature.sig, 'hex'))).to.be.false;
          });
        });
      }
    });
  });

  describe('from public key (compressed, valid sigs)', function () {
    valid.forEach(function (fixture) {
      var key = new Key({ public: new Buffer(fixture.pub, 'hex') });

      if (fixture.signatures) {
        fixture.signatures.forEach(function (signature, i) {
          var hash = sha256(signature.data);

          it('verify signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.verify(hash, new Buffer(signature.sig, 'hex'))).to.be.true;
          });
        });
      }
    });
  });

  describe('from public key (compressed, invalid sigs)', function () {
    invalid.forEach(function (fixture) {
      var key = new Key({ public: new Buffer(fixture.pub, 'hex') });

      if (fixture.signatures) {
        fixture.signatures.forEach(function (signature, i) {
          var hash = sha256(signature.data);

          it('not verify signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.verify(hash, new Buffer(signature.sig, 'hex'))).to.be.false;
          });
        });
      }
    });
  });

  describe('from public key (uncompressed, valid sigs)', function () {
    valid.forEach(function (fixture) {
      var key = new Key({ public: new Buffer(fixture.pubUncompressed, 'hex') });

      if (fixture.signatures) {
        fixture.signatures.forEach(function (signature, i) {
          var hash = sha256(signature.data);

          it('verify signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.verify(hash, new Buffer(signature.sig, 'hex'))).to.be.true;
          });
        });
      }
    });
  });

  describe('from public key (uncompressed, invalid sigs)', function () {
    invalid.forEach(function (fixture) {
      var key = new Key({ public: new Buffer(fixture.pubUncompressed, 'hex') });

      if (fixture.signatures) {
        fixture.signatures.forEach(function (signature, i) {
          var hash = sha256(signature.data);

          it('not verify signature of \'' + signature.data.substring(0, 10) + '...\' for ' + fixture.prv, function () {
            expect(key.verify(hash, new Buffer(signature.sig, 'hex'))).to.be.false;
          });
        });
      }
    });
  });
});
