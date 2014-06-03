#include <node.h>
#include <node_buffer.h>
#include <nan.h>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include "key.h"

using namespace v8;
using namespace node;

Persistent<FunctionTemplate> Key::constructor;

Key::Key() {
  hasPrivate = false;
  hasPublic = false;
  ec = EC_KEY_new_by_curve_name(NID_secp256k1);
}

Key::~Key() {
  EC_KEY_free(ec);
}

void
Key::Initialize(Handle<Object> target) {
  NanScope();

  Local<FunctionTemplate> ctor = NanNew<FunctionTemplate>(New);
  NanAssignPersistent(constructor, ctor);
  ctor->InstanceTemplate()->SetInternalFieldCount(1);
  ctor->SetClassName(NanNew("Key"));

  Local<ObjectTemplate> proto = ctor->PrototypeTemplate();
  NODE_SET_PROTOTYPE_METHOD(ctor, "regenerate", Regenerate);
  NODE_SET_PROTOTYPE_METHOD(ctor, "sign", Sign);
  NODE_SET_PROTOTYPE_METHOD(ctor, "verify", Verify);

  proto->SetAccessor(NanNew("prv"), GetPrv, SetPrv);
  proto->SetAccessor(NanNew("pub"), GetPub, SetPub);
  proto->SetAccessor(NanNew("pubUncompressed"), GetPubUncompressed, SetPub);

  target->Set(NanNew("Key"), ctor->GetFunction());
}

NAN_METHOD(Key::New) {
  NanScope();
  Key *key = new Key();
  if (args.Length() == 1 && args[0]->IsBoolean() && args[0]->BooleanValue()) {
    EC_KEY_generate_key(key->ec);
    key->hasPublic = true;
    key->hasPrivate = true;
  }
  key->Wrap(args.This());
  NanReturnValue(args.This());
}

NAN_GETTER(Key::GetPrv) {
  NanScope();
  Key* key = ObjectWrap::Unwrap<Key>(args.This());
  if (!key->hasPrivate) {
    NanReturnUndefined();
  }
  const BIGNUM *prv = EC_KEY_get0_private_key(key->ec);
  int prv_size = BN_num_bytes(prv);

  Handle<Object> prv_buf = NanNewBufferHandle(32);
  unsigned char *prv_data = (unsigned char *)Buffer::Data(prv_buf);
  BN_bn2bin(prv, &prv_data[32 - prv_size]);
  NanReturnValue(prv_buf);
}

NAN_GETTER(Key::GetPub) {
  NanScope();
  Key* key = ObjectWrap::Unwrap<Key>(args.This());
  if (!key->hasPublic) {
    NanReturnUndefined();
  }
  EC_KEY_set_conv_form(key->ec, POINT_CONVERSION_COMPRESSED);

  int pub_size = i2o_ECPublicKey(key->ec, NULL);
  if (!pub_size) {
    NanReturnUndefined();
  }
  Handle<Object> pub_buf = NanNewBufferHandle(pub_size);
  unsigned char *pub_data = (unsigned char *)Buffer::Data(pub_buf);
  i2o_ECPublicKey(key->ec, &pub_data);
  NanReturnValue(pub_buf);
}

NAN_GETTER(Key::GetPubUncompressed) {
  NanScope();
  Key* key = ObjectWrap::Unwrap<Key>(args.This());
  if (!key->hasPublic) {
    NanReturnUndefined();
  }
  EC_KEY_set_conv_form(key->ec, POINT_CONVERSION_UNCOMPRESSED);

  int pub_size = i2o_ECPublicKey(key->ec, NULL);
  if (!pub_size) {
    NanReturnUndefined();
  }
  Handle<Object> pub_buf = NanNewBufferHandle(pub_size);
  unsigned char *pub_data = (unsigned char *)Buffer::Data(pub_buf);
  i2o_ECPublicKey(key->ec, &pub_data);
  NanReturnValue(pub_buf);
}

NAN_SETTER(Key::SetPrv) {
  NanScope();
  Key* key = ObjectWrap::Unwrap<Key>(args.This());
  Handle<Object> prv_buf = value->ToObject();
  const unsigned char *prv_data = (const unsigned char *)Buffer::Data(prv_buf);

  BIGNUM *prv = BN_bin2bn(prv_data, Buffer::Length(prv_buf), NULL);
  EC_KEY_set_private_key(key->ec, prv);
  BN_clear_free(prv);

  key->hasPrivate = true;
}

NAN_SETTER(Key::SetPub) {
  NanScope();
  Key* key = ObjectWrap::Unwrap<Key>(args.This());
  Handle<Object> pub_buf = value->ToObject();
  const unsigned char *pub_data = (const unsigned char *)Buffer::Data(pub_buf);

  if (!o2i_ECPublicKey(&(key->ec), &pub_data, Buffer::Length(pub_buf))) {
    NanThrowError("invalid public key");
  }
  key->hasPublic = true;
}

NAN_METHOD(Key::Regenerate) {
  NanScope();
  Key* key = ObjectWrap::Unwrap<Key>(args.This());
  if (!key->hasPrivate) {
    NanThrowError("requires private key");
  }

  const BIGNUM *prv = EC_KEY_get0_private_key(key->ec);
  const EC_GROUP *group = EC_KEY_get0_group(key->ec);
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *pub = EC_POINT_new(group);

  EC_POINT_mul(group, pub, prv, NULL, NULL, ctx);
  EC_KEY_set_public_key(key->ec, pub);

  key->hasPublic = true;

  EC_POINT_free(pub);
  BN_CTX_free(ctx);

  NanReturnUndefined();
}

NAN_METHOD(Key::Sign) {
  NanScope();
  Key* key = ObjectWrap::Unwrap<Key>(args.This());
  if (args.Length() != 1 && args.Length() != 2) {
    NanThrowError("One or two arguments expected: hash, [k]");
  }
  if (!Buffer::HasInstance(args[0])) {
    NanThrowError("Argument 'hash' must be of type Buffer");
  }
  if (!key->hasPrivate) {
    NanThrowError("Key does not have a private key set");
  }

  Handle<Object> hash_buf = args[0]->ToObject();
  const unsigned char *hash_data = (unsigned char *) Buffer::Data(hash_buf);
  if (Buffer::Length(hash_buf) != 32) {
    NanThrowError("Argument 'hash' must be Buffer of length 32 bytes");
  }

  BIGNUM* k = NULL;

  if (args.Length() == 2) {
    if (!Buffer::HasInstance(args[1])) {
      NanThrowError("Argument 'k' must be of type Buffer");
    }
    Handle<Object> k_buf = args[1]->ToObject();
    const unsigned char *k_data = (unsigned char *) Buffer::Data(k_buf);
    unsigned int k_len = Buffer::Length(k_buf);
    k = BN_bin2bn(k_data, k_len, NULL);
  }


  // Create signature
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *kinv = NULL, *rp = NULL,  *X = NULL,
    *order = BN_new(),
    *halforder = BN_new();
  EC_POINT *temp_point = NULL;
  ECDSA_SIG *sig = NULL;
  const EC_GROUP *group = EC_KEY_get0_group(key->ec);
  EC_GROUP_get_order(group, order, ctx);

  if (k == NULL) {
    sig = ECDSA_do_sign(hash_data, 32, key->ec);
  } else {
    kinv = BN_new();
    rp = BN_new();
    X = BN_new();

    // Get X from (k x G)
    temp_point = EC_POINT_new(group);
    EC_POINT_mul(group, temp_point, k, NULL, NULL, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, temp_point, X, NULL, ctx);

    // Calculate r and k^-1
    BN_nnmod(rp, X, order, ctx);
    BN_mod_inverse(kinv, k, order, ctx);

    sig = ECDSA_do_sign_ex(hash_data, 32, kinv, rp, key->ec);
  }

  // enforce low S values, by negating the value (modulo the order) if above order/2.
  BN_rshift1(halforder, order);
  if (BN_cmp(sig->s, halforder) > 0) {
    BN_sub(sig->s, order, sig->s);
  }

  Handle<Object> sig_buf = NanNewBufferHandle(64);
  unsigned char *sig_data = (unsigned char *)Buffer::Data(sig_buf);

  BN_bn2bin(sig->r, &sig_data[0]);
  BN_bn2bin(sig->s, &sig_data[32]);

  if (kinv != NULL)
    BN_clear_free(kinv);
  if (rp != NULL)
    BN_clear_free(rp);
  if (X != NULL)
    BN_clear_free(X);
  if (k != NULL)
    BN_clear_free(k);
  if (temp_point != NULL)
    EC_POINT_free(temp_point);
  BN_clear_free(order);
  BN_clear_free(halforder);
  BN_CTX_free(ctx);
  ECDSA_SIG_free(sig);

  NanReturnValue(sig_buf);
}

NAN_METHOD(Key::Verify) {
  NanScope();
  Key* key = node::ObjectWrap::Unwrap<Key>(args.This());
  if (args.Length() != 2) {
    NanThrowError("Two arguments expected: hash, sig");
  }
  if (!Buffer::HasInstance(args[0])) {
    NanThrowError("Argument 'hash' must be of type Buffer");
  }
  if (!Buffer::HasInstance(args[1])) {
    NanThrowError("Argument 'sig' must be of type Buffer");
  }
  if (!key->hasPublic) {
    NanThrowError("Key does not have a public key set");
  }

  Handle<Object> hash_buf = args[0]->ToObject();
  Handle<Object> sig_buf = args[1]->ToObject();

  const unsigned char *hash_data = (unsigned char *) Buffer::Data(hash_buf);
  const unsigned char *sig_data = (unsigned char *) Buffer::Data(sig_buf);

  if (Buffer::Length(hash_buf) != 32) {
    NanThrowError("Argument 'hash' must be Buffer of length 32 bytes");
  }

  // Verify signature
  ECDSA_SIG *sig = ECDSA_SIG_new();
  sig->r = BN_bin2bn(&sig_data[0], 32, BN_new());
  sig->s = BN_bin2bn(&sig_data[32], 32, BN_new());

  int der_size = i2d_ECDSA_SIG(sig, NULL);
  unsigned char *der_begin, *der_end;
  der_begin = der_end = (unsigned char *)malloc(der_size);

  i2d_ECDSA_SIG(sig, &der_end);

  int result = ECDSA_verify(0, hash_data, 32, der_begin, der_size, key->ec);

  free(der_begin);
  ECDSA_SIG_free(sig);

  if (result == -1) {
    NanThrowError("Error during ECDSA_verify");
  } else if (result == 0) {
    // Signature invalid
    return scope.Close(Boolean::New(false));
  } else if (result == 1) {
    // Signature valid
    return scope.Close(Boolean::New(true));
  } else {
    NanThrowError("ECDSA_verify gave undefined return value");
  }
  NanReturnUndefined();
}

extern "C" void
init (Handle<Object> target) {
  Key::Initialize(target);
}

NODE_MODULE(KeyModule, init)
