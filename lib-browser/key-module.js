var sjcl = require('core-sjcl');
var b = sjcl.bitArray;
var ecc = sjcl.ecc;
var curve = ecc.curves.k256;

var toBits = sjcl.codec.bytes.toBits;
var toBytes = sjcl.codec.bytes.fromBits;
function toBuffer(bits) {
  return new Buffer(toBytes(bits));
}

function KeyModule() {
  this.private = null;
  this.public = null;
  this.compressed = true;
}

Object.defineProperty(KeyModule.prototype, 'public', {
  get: function () {
    var pubPoint = this._keypair.pub._point;
    var enc = toBytes(pubPoint.x.toBits());
    var y = toBytes(pubPoint.y.toBits());
    var even = pubPoint.y.mod(2).equals(0);
    if (this.compressed) {
      enc = [even ? 0x02 : 0x03].concat(enc);
    } else {
      enc = [0x04].concat(enc, y);
    }
    return new Buffer(enc);
  },
  set: function (value) {
    this._public = value;
  }
});

KeyModule.prototype.regenerateSync = function () {
  this._keypair = ecc.ecdsa.generateKeys(curve, 0, sjcl.bn.fromBits(toBits(this.private)));
};

KeyModule.prototype.signSync = function (hash, k) {
  var sig = this._keypair.sec.sign(toBits(hash), null, null, sjcl.bn.fromBits(toBits(k)));

  var q = this._keypair.sec._curve.r.copy();
  var l = q.bitLength();
  var r = b.bitSlice(sig, 0, l);
  var s = sjcl.bn.fromBits(b.bitSlice(sig, l, l * 2));

  var halfQ = q.copy().halveM();
  if (s.greaterEquals(halfQ)) {
    q.subM(s);
    sig = b.concat(r, q.toBits(l));
  }

  return toBuffer(sig);
};

KeyModule.prototype.verifySignatureSync = function (hash, signature) {
  return this._keypair.pub.verify(toBits(hash), toBits(signature));
};

module.exports = KeyModule;
