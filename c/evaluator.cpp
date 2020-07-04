#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/evaluator.h"
#include "seal/util/locks.h"
#include "seal/plaintext.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
     extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

     extern ReaderWriterLocker pointer_store_locker_;

void* Evaluator_ctor(void* context_p) {
    SEALContext* cp = (SEALContext*)context_p;
    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(cp);
    if (ctxiter == pointer_store_.end())
    {
	cout << "###wrong shared" << endl;
        //return null_context_;
    }

    return new Evaluator(ctxiter->second);
  
}

void Evaluator_square(void* p, void* encrypted, void* dest) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    Ciphertext* dest_p= (Ciphertext*)dest;
    evaluator_p->square(*encrypted_p, *dest_p);
}

void Evaluator_relinearize_inplace(void* p, void* encrypted, void* relinKeys) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    RelinKeys* relinKeys_p = (RelinKeys*)relinKeys;

    evaluator_p->relinearize_inplace(*encrypted_p, *relinKeys_p);
}

void Evaluator_rescale_to_next_inplace(void* p, void* encrypted) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    evaluator_p->rescale_to_next_inplace(*encrypted_p);
}

void Evaluator_multiply_plain(void* p, void* encrypted, void* plaintext, void* dest) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    Ciphertext* dest_p = (Ciphertext*)dest;

    evaluator_p->multiply_plain(*encrypted_p, *plaintext_p, *dest_p);
}

void Evaluator_multiply_inplace(void* p, void* encrypted1, void* encrypted2) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted1_p = (Ciphertext*)encrypted1;
    Ciphertext* encrypted2_p = (Ciphertext*)encrypted2;
    
    evaluator_p->multiply_inplace(*encrypted1_p, *encrypted2_p);

}

void Evaluator_multiply(void* p, void* encrypted1, void* encrypted2, void* destination) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted1_p = (Ciphertext*)encrypted1;
    Ciphertext* encrypted2_p = (Ciphertext*)encrypted2;
    Ciphertext* destination_p = (Ciphertext*)destination;
    evaluator_p->multiply(*encrypted1_p, *encrypted2_p, *destination_p);
}

void Evaluator_multiply_plain_inplace(void* p, void* encrypted, void* plaintext) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    
    evaluator_p->multiply_plain_inplace(*encrypted_p, *plaintext_p);
}

void Evaluator_mod_switch_to_inplace(void* p, void* encrypted, void* block) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    long* block_p = (long*)block;
    parms_id_type parms;
    std::copy_n(block_p, parms.size(), std::begin(parms));
    evaluator_p->mod_switch_to_inplace(*encrypted_p, parms);
}

void Evaluator_mod_switch_to_inplace_plain(void* p, void* plain, void* block) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Plaintext* plain_p = (Plaintext*)plain;;
    long* block_p = (long*)block;
    parms_id_type parms;
    std::copy_n(block_p, parms.size(), std::begin(parms));
    evaluator_p->mod_switch_to_inplace(*plain_p, parms);
}

void Evaluator_mod_switch_to_next_inplace(void* p, void* encrypted) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    evaluator_p->mod_switch_to_next_inplace(*encrypted_p);
}

void Evaluator_add(void* p, void* encrypted1, void* encrypted2, void* dest) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted1_p = (Ciphertext*)encrypted1;
    Ciphertext* encrypted2_p = (Ciphertext*)encrypted2;
    Ciphertext* dest_p = (Ciphertext*)dest;
    evaluator_p->add(*encrypted1_p, *encrypted2_p, *dest_p);
}

void Evaluator_add_plain_inplace(void* p, void* encrypted1, void* plaintext) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted1_p = (Ciphertext*)encrypted1;
    Plaintext* plaintext_p = (Plaintext*)plaintext;
    evaluator_p->add_plain_inplace(*encrypted1_p, *plaintext_p);
}

void Evaluator_add_inplace(void* p, void* encrypted1, void* encrypted2) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted1_p = (Ciphertext*)encrypted1;
    Ciphertext* encrypted2_p = (Ciphertext*)encrypted2;
    evaluator_p->add_inplace(*encrypted1_p, *encrypted2_p);
}

void Evaluator_square_inplace(void* p, void* encrypted) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    evaluator_p->square_inplace(*encrypted_p);
}

void Evaluator_rotate_vector_inplace(void* p, void* encrypted, int steps, void* galoisKeys) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    GaloisKeys* galoiskeys_p = (GaloisKeys*)galoisKeys;
    evaluator_p->rotate_vector_inplace(*encrypted_p, steps, *galoiskeys_p);
}

void Evaluator_complex_conjugate_inplace(void* p, void* encrypted, void* galoisKeys) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    GaloisKeys* galoiskeys_p = (GaloisKeys*)galoisKeys;
    evaluator_p->complex_conjugate_inplace(*encrypted_p, *galoiskeys_p);
}

void Evaluator_rotate_rows_inplace(void* p, void* encrypted, int steps, void* galoisKeys) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    GaloisKeys* galoiskeys_p = (GaloisKeys*)galoisKeys;
    evaluator_p->rotate_rows_inplace(*encrypted_p, steps, *galoiskeys_p);
}

void Evaluator_rotate_columns_inplace(void* p, void* encrypted, void* galoisKeys) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    GaloisKeys* galoiskeys_p = (GaloisKeys*)galoisKeys;
    evaluator_p->rotate_columns_inplace(*encrypted_p, *galoiskeys_p);
}

void Evaluator_rotate_vector(void* p, void* encrypted, int steps, void* galoisKeys, void* destination) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    GaloisKeys* galoiskeys_p = (GaloisKeys*)galoisKeys;
    Ciphertext* destination_p = (Ciphertext*)destination;
    evaluator_p->rotate_vector(*encrypted_p, steps, *galoiskeys_p, *destination_p);
}

void Evaluator_negate(void* p, void* encrypted, void* destination) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    Ciphertext* destination_p = (Ciphertext*)destination;
    evaluator_p->negate(*encrypted_p, *destination_p);
}

void Evaluator_add_plain(void* p, void* encrypted, void* plain, void* destination) {
    Evaluator* evaluator_p = (Evaluator*)p;
    Ciphertext* encrypted_p = (Ciphertext*)encrypted;
    Plaintext* plain_p = (Plaintext*)plain;
    Ciphertext* destination_p = (Ciphertext*)destination;
    evaluator_p->add_plain(*encrypted_p, *plain_p, *destination_p);
}

}
