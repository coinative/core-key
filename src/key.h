#ifndef COINATIVE_KEY_H_
#define COINATIVE_KEY_H_

#include <node.h>
#include <nan.h>

using namespace v8;
using namespace node;

class Key : ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Init();

    static NAN_METHOD(New);

    static NAN_GETTER(GetPrv);
    static NAN_GETTER(GetPub);
    static NAN_GETTER(GetPubUncompressed);
    static NAN_SETTER(SetPrv);
    static NAN_SETTER(SetPub);

    static NAN_METHOD(Regenerate);
    static NAN_METHOD(Sign);
    static NAN_METHOD(Verify);

    Key();

  private:
    ~Key();

    EC_KEY *ec;
    bool hasPrivate;
    bool hasPublic;
};

#endif
