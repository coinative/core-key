var KeyModule = require('./key-module');
var hmacsha256 = require('core-hash').hmacsha256;

function Key(options) {
  this.keyModule = new KeyModule();
  this.compressed = typeof options.compressed === 'undefined' ? true : options.compressed;
  if (options.prv) {
    this.prv = options.prv;
    this.keyModule.regenerateSync();
  } else if (options.pub) {
    this.pub = options.pub;
  }
}

Object.defineProperty(Key.prototype, 'compressed', {
  get: function () {
    return this._compressed;
  },
  set: function (value) {
    this._compressed = value;
    this.keyModule.compressed = value;
  }
});

Object.defineProperty(Key.prototype, 'prv', {
  get: function () {
    return this._prv;
  },
  set: function (value) {
    this._prv = value;
    this.keyModule.prv = value;
  }
});

Object.defineProperty(Key.prototype, 'pub', {
  get: function () {
    return this.keyModule.pub;
  },
  set: function (value) {
    this.keyModule.pub = value;
  }
});

Key.prototype.sign = function (hash) {
  var k = Key.generateK(this.prv, hash);
  return this.keyModule.signSync(hash, k);
};

Key.prototype.verify = function (hash, signature) {
  return this.keyModule.verifySignatureSync(hash, signature);
};

// rfc6979
Key.generateK = function(prv, hash) {
  var v = new Buffer(32);
  var k = new Buffer(32);
  v.fill(0x01);
  k.fill(0x00);
  k = hmacsha256(k, Buffer.concat([v, new Buffer([0x00]), prv, hash]));
  v = hmacsha256(k, v);
  k = hmacsha256(k, Buffer.concat([v, new Buffer([0x01]), prv, hash]));
  v = hmacsha256(k, v);
  v = hmacsha256(k, v);
  return v;
};

module.exports = Key;
