#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/modulus.h"

using namespace std;
using namespace seal;

extern "C" {
//TODO: repeat
void BuildSmallModulusPointers(const vector<SmallModulus> &in_mods, long *length, void **out_mods)
{
    *length = static_cast<uint64_t>(in_mods.size());
    if (out_mods == nullptr)
    {
        // The caller is only interested in the size
        return;
    }

    SmallModulus* *mod_ptr_array = reinterpret_cast<SmallModulus**>(out_mods);
    transform(in_mods.begin(), in_mods.end(), mod_ptr_array,
        [](const auto &mod) { return new SmallModulus(mod); }
    );
}

void CoeffModulus_create(long poly_modulus_degree, long length, void* bitSizeArr, void** coeffArray) {
    vector<int> bit_sizes_vec;
    int* bitsize_p = (int*)bitSizeArr;
    copy_n(bitsize_p, length, back_inserter(bit_sizes_vec));
    vector<SmallModulus> result;
    
    for (int i = 0; i < length; i++) {
      cout << "##pos1:" << bit_sizes_vec[i] << endl;
    }
    try
    {
        result = CoeffModulus::Create(poly_modulus_degree, bit_sizes_vec);
    }
    catch (const invalid_argument&)
    {
        cout<<"##error1"<<endl;;
    }
    catch (const logic_error&)
    {
        cout<<"##error2"<<endl;;
    }
    for (int i = 0 ; i < result.size(); i++) {
       cout << "in c value:" << result[i].value() << endl;
    }
    BuildSmallModulusPointers(result, &length, coeffArray);
}

long SmallModulus_getValue(void* self) {
    SmallModulus* p = (SmallModulus*)self;
    return p->value();
}

void* SmallModulus_ctor(long value) {
    return new SmallModulus(value);
}

void CoeffModulus_BFVDefault(long poly_modulus_degree, int sec_level, void* len_p, void** coeffArray) {
    long* length = (long*)len_p;
    sec_level_type security_level = static_cast<sec_level_type>(sec_level);
    vector<SmallModulus> result;
    try
    {
        result = CoeffModulus::BFVDefault(poly_modulus_degree, security_level);
    }
    catch (const invalid_argument&)
    {
        cout << "wrong value" << endl;;
    }
    BuildSmallModulusPointers(result, length, coeffArray);

}


}
