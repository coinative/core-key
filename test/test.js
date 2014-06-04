var Key = require('../');
var sha256 = require('core-hash').sha256;

var valid = require('./fixtures/valid.json');
var invalid = require('./fixtures/invalid.json');

describe('key', function () {
  it('should throw \'invalid public key\' when the public key is not on the curve', function () {
    expect(function () {
      new Key({ pub: new Buffer('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81700', 'hex') });
    }).to.throw('invalid public key');
  });

  describe('from private key (valid sigs)', function () {
    valid.forEach(function (fixture) {
      var key = new Key({ prv: new Buffer(fixture.prv, 'hex') });

      describe('private key: ' + fixture.prv, function () {
        it('generate public keys', function () {
          expect(key.pub.toString('hex')).to.equal(fixture.pub);
          expect(key.pubUncompressed.toString('hex')).to.equal(fixture.pubUncompressed);
        });

        it('generate correct address', function () {
          expect(key.getAddress().toString()).to.equal(fixture.address);
        });

        if (fixture.signatures) {
          fixture.signatures.forEach(function (signature, i) {
            var hash = sha256(signature.data);

            it('generate correct k #' + i, function () {
              expect(Key.generateK(new Buffer(fixture.prv, 'hex'), hash).toString('hex')).to.equal(signature.k);
            });

            it('generate correct signature of \'' + signature.data.substring(0, 10) + '...\'', function () {
              expect(key.sign(hash).toString('hex')).to.equal(signature.sig);
            });

            it('verify signature of \'' + signature.data.substring(0, 10) + '...\'', function () {
              expect(key.verify(hash, new Buffer(signature.sig, 'hex'))).to.be.true;
            });
          });
        }
      });
    });
  });

  describe('from private key (invalid sigs)', function () {
    invalid.forEach(function (fixture) {
      var key = new Key({ prv: new Buffer(fixture.prv, 'hex') });

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
      var key = new Key({ pub: new Buffer(fixture.pub, 'hex') });

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
      var key = new Key({ pub: new Buffer(fixture.pub, 'hex') });

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
      var key = new Key({ pub: new Buffer(fixture.pubUncompressed, 'hex') });

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
      var key = new Key({ pub: new Buffer(fixture.pubUncompressed, 'hex') });

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
