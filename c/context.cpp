#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/util/locks.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {
unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

ReaderWriterLocker pointer_store_locker_;

void* SealContext_ctor(void* encParam, bool expandModChain, int secLevel) {
    EncryptionParameters* encparam_p = (EncryptionParameters*)encParam;
    sec_level_type security_level = static_cast<sec_level_type>(secLevel);
    auto result = SEALContext::Create(*encparam_p, expandModChain, security_level); 

    WriterLock lock(pointer_store_locker_.acquire_write());
    pointer_store_[result.get()] = result;
cout << "##inc createcontext param set:" << result.get()->parameters_set() << endl;
    return result.get();
}

void* SealContext_getKeyContextData(void* p) {
    SEALContext* context_p = (SEALContext*)p;
    auto data = context_p->key_context_data();
    const SEALContext::ContextData* data_p = const_cast<SEALContext::ContextData*>(data.get());
    return (void*)data_p;
}

void* SealContext_getFirstContextData(void* p) {
    SEALContext* context_p = (SEALContext*)p;
    auto data = context_p->first_context_data();
    const SEALContext::ContextData* data_p = const_cast<SEALContext::ContextData*>(data.get());
    return (void*)data_p;
}

void SealContext_ContextData_get_total_coeff_modulus(void* data_p, void* len_p, void* total_coeff_modulus_p) {
    SEALContext::ContextData *cont_data = (SEALContext::ContextData*)data_p;

    auto len = cont_data->parms().coeff_modulus().size();
    long* len_p1 = (long*)len_p;
    *len_p1 = len;

    if (total_coeff_modulus_p == NULL) {
      return;
    }

    long* total_coeff_modulus = (long*)total_coeff_modulus_p;
    for (uint64_t i = 0; i < *len_p1; i++)
    {
        total_coeff_modulus[i] = cont_data->total_coeff_modulus()[i];
        cout << "##inc:"<< total_coeff_modulus[i] << endl;
    }
}

void* SealContext_ContextData_getParams(void* data_p) {
    SEALContext::ContextData *cont_data = (SEALContext::ContextData*)data_p;
    EncryptionParameters* param = new EncryptionParameters(cont_data->parms());
    return param;
}

void* SealContext_getContextData(void* p, void* block) {
    SEALContext* context_p = (SEALContext*)p;
    long* block_p = (long*)block;
    parms_id_type parms;
    std::copy_n(block_p, parms.size(), std::begin(parms));
    auto data = context_p->get_context_data(parms);
    const SEALContext::ContextData* data_p = const_cast<SEALContext::ContextData*>(data.get());
    return (void*)data_p;
}

long SealContext_ContextData_get_chain_index(void* data_p) {
    SEALContext::ContextData *cont_data = (SEALContext::ContextData*)data_p;
    return cont_data->chain_index();    
}

bool SealContext_using_keyswitching(void* p) {
    SEALContext* context_p = (SEALContext*)p;
    return context_p->using_keyswitching();
}

void* SealContext_ContextData_getQualifiers(void* data_p) {
    SEALContext::ContextData *cont_data = (SEALContext::ContextData*)data_p;
    EncryptionParameterQualifiers *qualifiers = new EncryptionParameterQualifiers(cont_data->qualifiers());
    return qualifiers;
}

int EPQ_sec_level(void* p) {
    EncryptionParameterQualifiers *qualifiers = (EncryptionParameterQualifiers*)p;
    return (int)qualifiers->sec_level;
}

bool EPQ_using_batching(void* p) {
    EncryptionParameterQualifiers *qualifiers = (EncryptionParameterQualifiers*)p;
    return qualifiers->using_batching;
}

void SealContext_get_first_params_id(void* p, void* block) {
    SEALContext* context_p = (SEALContext*)p;
    long* block_p = (long*)block;
    const seal::parms_id_type& paramsId = context_p->first_parms_id();
    std::copy_n(std::cbegin(paramsId), paramsId.size(), block_p);
}

void SealContext_get_last_params_id(void* p, void* block) {
    SEALContext* context_p = (SEALContext*)p;
    long* block_p = (long*)block;
    const seal::parms_id_type& paramsId = context_p->last_parms_id();
    std::copy_n(std::cbegin(paramsId), paramsId.size(), block_p);
}

void* SealContext_ContextData_get_next_context_data(void* data_p) {
    SEALContext::ContextData *cont_data = (SEALContext::ContextData*)data_p;
    return const_cast<SEALContext::ContextData*>(cont_data->next_context_data().get());
}

}
