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

void SecretKey_get_paramsId(void* p, void* block) {
    SecretKey* secret_key_p = (SecretKey*)p;
    long* block_p = (long*)block;
    const seal::parms_id_type& paramsId = secret_key_p->parms_id();
    std::copy_n(std::cbegin(paramsId), paramsId.size(), block_p);
}

}
