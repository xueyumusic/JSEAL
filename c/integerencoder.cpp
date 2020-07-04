#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/encryptor.h"
#include "seal/intencoder.h"
#include "seal/util/locks.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
     extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

     extern ReaderWriterLocker pointer_store_locker_;

void* IntegerEncoder_ctor(void* context_p) {
    SEALContext* cp = (SEALContext*)context_p;
    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(cp);
    if (ctxiter == pointer_store_.end())
    {
	cout << "###wrong shared" << endl;
        //return null_context_;
    }

    return new IntegerEncoder(ctxiter->second);
  
}

void IntegerEncoder_encode(void* p, long value, void* destination) {
    IntegerEncoder* encoder = (IntegerEncoder*)p;
    Plaintext* destination_p = (Plaintext*)destination;
    int64_t value1 = (int64_t)value;
    encoder->encode(value1, *destination_p);
}

int IntegerEncoder_decode_int32(void* p, void* plain) {
    IntegerEncoder* encoder = (IntegerEncoder*)p;
    Plaintext* plain_p = (Plaintext*)plain;
    return encoder->decode_int32(*plain_p);
}

/*
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
*/

}

