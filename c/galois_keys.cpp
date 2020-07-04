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

void GaloisKeys_get_paramsId(void* p, void* block) {
    GaloisKeys* galois_keys_p = (GaloisKeys*)p;
    long* block_p = (long*)block;
    const seal::parms_id_type& paramsId = galois_keys_p->parms_id();
    std::copy_n(std::cbegin(paramsId), paramsId.size(), block_p);
}

}
