var KeyModule = require('./key-module');
var hmacsha256 = require('core-hash').hmacsha256;

function Key(options) {
  this.keyModule = new KeyModule();
  this.compressed = typeof options.compressed === 'undefined' ? true : options.compressed;
  if (options.private) {
    this.private = options.private;
    this.keyModule.regenerateSync();
  } else if (options.public) {
    this.public = options.public;
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

Object.defineProperty(Key.prototype, 'private', {
  get: function () {
    return this._private;
  },
  set: function (value) {
    this._private = value;
    this.keyModule.private = value;
  }
});

Object.defineProperty(Key.prototype, 'public', {
  get: function () {
    return this.keyModule.public;
  },
  set: function (value) {
    this.keyModule.public = value;
  }
});

Key.prototype.sign = function (hash) {
  var k = Key.generateK(this.private, hash);
  return this.keyModule.signSync(hash, k);
};

Key.prototype.verify = function (hash, signature) {
  return this.keyModule.verifySignatureSync(hash, signature);
};

// rfc6979
Key.generateK = function(private, hash) {
  var v = new Buffer(32);
  var k = new Buffer(32);
  v.fill(0x01);
  k.fill(0x00);
  k = hmacsha256(k, Buffer.concat([v, new Buffer([0x00]), private, hash]));
  v = hmacsha256(k, v);
  k = hmacsha256(k, Buffer.concat([v, new Buffer([0x01]), private, hash]));
  v = hmacsha256(k, v);
  v = hmacsha256(k, v);
  return v;
};

module.exports = Key;
