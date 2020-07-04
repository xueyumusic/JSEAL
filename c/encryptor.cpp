#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/encryptor.h"
#include "seal/util/locks.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
     extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

     extern ReaderWriterLocker pointer_store_locker_;

void* Encryptor_ctor(void* context_p, void* publicKey) {
    SEALContext* cp = (SEALContext*)context_p;
    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(cp);
    if (ctxiter == pointer_store_.end())
    {
	cout << "###wrong shared" << endl;
        //return null_context_;
    }

    PublicKey* pk_p = (PublicKey*)publicKey;
    return new Encryptor(ctxiter->second, *pk_p);
  
}

void Encryptor_encrypt(void* p, void* plaintext, void* ciphertext) {
    Encryptor* encryptor = (Encryptor*)p; 
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    Ciphertext* ciphertext_p = (Ciphertext*)ciphertext;
    encryptor->encrypt(*plaintext_p, *ciphertext_p);
}


}
