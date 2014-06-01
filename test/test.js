var Key = require('../');
var sha256 = require('core-hash').sha256;

var fixtures = require('./fixtures/valid.json');

describe('key', function () {
  fixtures.forEach(function (fixture) {
    var key = new Key({ private: new Buffer(fixture.prv, 'hex') });

    it('generate public keys for ' + fixture.prv, function () {
      if (fixture.pub) {
        expect(key.public.toString('hex')).to.equal(fixture.pub);
      }
      if (fixture.pubUncompressed) {
        key.compressed = false;
        expect(key.public.toString('hex')).to.equal(fixture.pubUncompressed);
      }
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
      });
    }
  });
});
