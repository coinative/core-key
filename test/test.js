var Key = require('../');
var sha256 = require('core-hash').sha256;

var valid = require('./fixtures/valid.json');

describe('key', function () {
  describe('from private key', function () {
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

  describe('from public key (compressed)', function () {
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

  describe('from public key (uncompressed)', function () {
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
});
