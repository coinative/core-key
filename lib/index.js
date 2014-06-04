var Address = require('core-address');
var KeyModule = require('./key-module');
var hash160 = require('core-hash').hash160;
var hmacsha256 = require('core-hash').hmacsha256;

function Key(options) {
  this.keyModule = new KeyModule();
  if (options.prv) {
    this.prv = options.prv;
    this.keyModule.regenerate();
  } else if (options.pub) {
    this.pub = options.pub;
  }
  this.network = options.network || 'mainnet';
}

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

Object.defineProperty(Key.prototype, 'pubUncompressed', {
  get: function () {
    return this.keyModule.pubUncompressed;
  },
  set: function (value) {
    this.keyModule.pubUncompressed = value;
  }
});

Key.prototype.getAddress = function () {
  var hash = hash160(this.pub);
  return new Address(hash, 'pubkeyhash', this.network);
};

Key.prototype.sign = function (hash) {
  var k = Key.generateK(this.prv, hash);
  return this.keyModule.sign(hash, k);
};

Key.prototype.verify = function (hash, signature) {
  return this.keyModule.verify(hash, signature);
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
