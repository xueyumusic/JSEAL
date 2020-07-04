#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/util/locks.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
     extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

     extern ReaderWriterLocker pointer_store_locker_;


void* KeyGenerator_ctor(void* context_p) {
	SEALContext* cp = (SEALContext*)context_p;
    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(cp);
    if (ctxiter == pointer_store_.end())
    {
	cout << "###wrong shared" << endl;
        //return null_context_;
    }
   cout << "##inc ctx scheme:" << int(cp->key_context_data()->parms().scheme()) << endl;
   cout << "##inc param set:" << cp->parameters_set() << endl;
   void* p =  new KeyGenerator(ctxiter->second);
   cout << "##key p:" << p <<endl;
   return p;
}

void* KeyGenerator_get_publicKey(void* p) {
    KeyGenerator* gen = (KeyGenerator*)p;
    PublicKey* pk =  new PublicKey(gen->public_key());
    cout << "##inc pk:"<<pk<<endl;
    return pk;
}

void* KeyGenerator_get_secretKey(void* p) {
    KeyGenerator* gen = (KeyGenerator*)p;
    SecretKey* sk =  new SecretKey(gen->secret_key());
    cout << "##inc sk:"<<sk<<endl;
    return sk;
}
void* KeyGenerator_get_relinKeys(void* p) {
    KeyGenerator* gen = (KeyGenerator*)p;
    RelinKeys* rk =  new RelinKeys(gen->relin_keys());
    cout << "##inc rk:"<<rk<<endl;
    return rk;
}

void* KeyGenerator_get_galoisKeys(void* p) {
    KeyGenerator* gen = (KeyGenerator*)p;
    GaloisKeys* gk =  new GaloisKeys(gen->galois_keys());
    cout << "##inc gk:"<<gk<<endl;
    return gk;
}
}
