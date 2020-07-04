#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/decryptor.h"
#include "seal/util/locks.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
     extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

     extern ReaderWriterLocker pointer_store_locker_;

void* Decryptor_ctor(void* context_p, void* secretKey) {
    SEALContext* cp = (SEALContext*)context_p;
    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(cp);
    if (ctxiter == pointer_store_.end())
    {
	cout << "###wrong shared" << endl;
        //return null_context_;
    }

    SecretKey* sk_p = (SecretKey*)secretKey;
    return new Decryptor(ctxiter->second, *sk_p);
  
}


void Decryptor_decrypt(void* p, void* ciphertext, void* plaintext) {
    Decryptor* decryptor = (Decryptor*)p; 
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    Ciphertext* ciphertext_p = (Ciphertext*)ciphertext;
    decryptor->decrypt(*ciphertext_p, *plaintext_p);
}

int Decryptor_invariant_noise_budget(void* p, void* encrypted) {
    Decryptor* decryptor = (Decryptor*)p;
    Ciphertext* ciphertext_p = (Ciphertext*)encrypted;
    return decryptor->invariant_noise_budget(*ciphertext_p);
}


}
