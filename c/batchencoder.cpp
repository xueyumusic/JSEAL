#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/encryptor.h"
#include "seal/ckks.h"
#include "seal/batchencoder.h"
#include "seal/util/locks.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
     extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

     extern ReaderWriterLocker pointer_store_locker_;

void* BatchEncoder_ctor(void* context_p) {
    SEALContext* cp = (SEALContext*)context_p;
    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(cp);
    if (ctxiter == pointer_store_.end())
    {
	cout << "###wrong shared" << endl;
        //return null_context_;
    }

    return new BatchEncoder(ctxiter->second);
  
}

long BatchEncoder_slot_count(void* p) {
    BatchEncoder* batch_encoder_p = (BatchEncoder*)p;
    return batch_encoder_p->slot_count();
}

void BatchEncoder_encode(void* batchencoder, void* values, int length, void* plaintext) {
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    BatchEncoder* batchencoder_p = (BatchEncoder*)batchencoder;
    uint64_t* values_p = (uint64_t*)values;
    vector<uint64_t> input(length);
    for (uint64_t i = 0; i < length; i++)
    {
        input[i] = values_p[i];
    }


    batchencoder_p->encode(input, *plaintext_p);

}

void BatchEncoder_decode(void* batchencoder, void* plaintext, void* len_p, void* destination) {
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    BatchEncoder* batchencoder_p = (BatchEncoder*)batchencoder;
    int* len = (int*)len_p;
    vector<uint64_t> dest;
    batchencoder_p->decode(*plaintext_p, dest);
    *len = dest.size();

    if (nullptr == destination) {
      return;
    }
    uint64_t* dest_p = (uint64_t*)destination;
    for (int i = 0; i < dest.size(); i++) {
      dest_p[i] = dest[i];
    }
}

/*
void CKKSEncoder_encode1(void* ckksencoder, void* values, int length, double scale, void* plaintext) {
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    CKKSEncoder* ckksencoder_p = (CKKSEncoder*)ckksencoder;
    double* values_p = (double*)values;
    vector<double> input(length);
    for (uint64_t i = 0; i < length; i++)
    {
        input[i] = values_p[i];
    }


    ckksencoder_p->encode(input, scale, *plaintext_p);

}

void CKKSEncoder_decode(void* ckksencoder, void* plaintext, void* len_p, void* destination) {
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    CKKSEncoder* ckksencoder_p = (CKKSEncoder*)ckksencoder;
    int* len = (int*)len_p;
    vector<double> dest;
    ckksencoder_p->decode(*plaintext_p, dest);
    *len = dest.size();

    if (nullptr == destination) {
      return;
    }
    double* dest_p = (double*)destination;
    for (int i = 0; i < dest.size(); i++) {
      dest_p[i] = dest[i];
    }
}

void CKKSEncoder_encode2(void* ckksencoder, long value, void* plaintext) {
    CKKSEncoder* ckksencoder_p = (CKKSEncoder*)ckksencoder;
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    ckksencoder_p->encode(value, *plaintext_p);

}
*/

}
