#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/encryptor.h"
#include "seal/util/locks.h"
#include "seal/plaintext.h"
#include "seal/ciphertext.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
     extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;
     extern ReaderWriterLocker pointer_store_locker_;

void* Ciphertext_ctor() {
    return new Ciphertext();;
  
}

void* Ciphertext_ctor1(void* context_p) {
    SEALContext* cp = (SEALContext*)context_p;
    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(cp);
    if (ctxiter == pointer_store_.end())
    {
	cout << "###wrong shared" << endl;
        //return null_context_;
    }
    
    return new Ciphertext(ctxiter->second);

}

double Ciphertext_get_scale(void* p) {
    Ciphertext* ciphertext_p = (Ciphertext*)p;
    return ciphertext_p->scale();
}

void Ciphertext_get_paramsId(void* p, void* block) {
    Ciphertext* ciphertext_p = (Ciphertext*)p;
    long* block_p = (long*)block;

    const seal::parms_id_type& paramsId = ciphertext_p->parms_id();
    std::copy_n(std::cbegin(paramsId), paramsId.size(), block_p);
}

void Ciphertext_set_scale(void* p, double value) {
    Ciphertext* ciphertext_p = (Ciphertext*)p;
    ciphertext_p->scale() = value;
}

void Ciphertext_reserve(void* p, long sizeCapacity) {
    Ciphertext* ciphertext_p = (Ciphertext*)p;
    ciphertext_p->reserve(sizeCapacity);
}
int Ciphertext_size(void* p) {
    Ciphertext* ciphertext_p = (Ciphertext*)p;
    return ciphertext_p->size();
} 


}
