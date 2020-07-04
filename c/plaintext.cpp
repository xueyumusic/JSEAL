#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/encryptor.h"
#include "seal/util/locks.h"
#include "seal/plaintext.h"

using namespace std;
using namespace seal;
using namespace seal::util;

extern "C" {

void* Plaintext_ctor() {
    return new Plaintext();;
}

void* Plaintext_ctor1(long capacity, long coeffCount) {
    return new Plaintext(capacity, coeffCount);
}

void* Plaintext_ctor2(const char* hexPoly) {
    string hexPolyStr(hexPoly);
    return new Plaintext(hexPolyStr);
}


void Plaintext_get_paramsId(void* p, void* block) {
    Plaintext* plaintext_p = (Plaintext*)p;
    long* block_p = (long*)block;

    const seal::parms_id_type& paramsId = plaintext_p->parms_id();
    std::copy_n(std::cbegin(paramsId), paramsId.size(), block_p);
}

double Plaintext_get_scale(void* p) {
    Plaintext* plaintext_p = (Plaintext*)p;
    return plaintext_p->scale();
}

const char* Plaintext_to_string(void* p) {
    Plaintext* plaintext_p = (Plaintext*)p;
    string str = plaintext_p->to_string();
    char* res = new char[str.length()+1];
    cout << "##in c str:" << str.c_str() <<endl;
    strcpy(res, str.c_str());
    return res;
}
}
