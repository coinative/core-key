var sjcl = require('core-sjcl');
var b = sjcl.bitArray;
var ecc = sjcl.ecc;
var curve = ecc.curves.k256;

var toBits = sjcl.codec.bytes.toBits;
var toBytes = sjcl.codec.bytes.fromBits;
function toBuffer(bits) {
  return new Buffer(toBytes(bits));
}

var _0x00 = [b.partial(8, 0x00)];
var _0x02 = [b.partial(8, 0x02)];
var Q = new sjcl.bn('3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c');

function pubToPoint(pub) {
  var even = b.bitSlice(pub, 0, 8);
  var xBits = b.concat(_0x00, b.bitSlice(pub, 8, 256 + 8));
  var yBits = b.concat(_0x00, b.bitSlice(pub, 256 + 8));

  var x = sjcl.bn.fromBits(xBits);
  var y = sjcl.bn.fromBits(yBits);

  // Decompress Y if necessary
  if (y.equals(0) && curve.field.modulus.mod(new sjcl.bn(4)).equals(new sjcl.bn(3))) {
    // y^2 = x^3 + ax^2 + b, so we need to perform sqrt to recover y
    var ySquared = curve.b.add(x.mul(curve.a.add(x.square())));
    var y = ySquared.powermod(Q, curve.field.modulus);

    if (y.mod(2).equals(0) !== b.equal(even, _0x02)) {
      y = curve.field.modulus.sub(y);
    }
  }
  // reserialise curve here, expection is thrown when point is not on curve.
  return ecc.curves.k256.fromBits(new ecc.point(curve, x, y).toBits());
}

function KeyModule() {
  this.private = null;
  this._public = null;
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
    if (!this.private) {
      try {
        this._keypair = {
          pub: new sjcl.ecc.ecdsa.publicKey(curve, pubToPoint(toBits(value)))
        };
      } catch (e) {
        throw new Error('invalid public key');
      }
    }
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
  // Unfortunately sjcl ecdsa verify throws an error on invalid signatures
  try {
    return this._keypair.pub.verify(toBits(hash), toBits(signature));
  } catch (e) {
    return false;
  }
};

module.exports = KeyModule;
