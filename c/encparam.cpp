#include "seal/encryptionparams.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;

extern "C" {
namespace seal
{
    /**
    Enables access to private members of seal::EncryptionParameters.
    */
    struct EncryptionParameters::EncryptionParametersPrivateHelper
    {
        static auto parms_id(const EncryptionParameters &parms)
        {
            return parms.parms_id();
        }
    };
}


//TODO: repeat
void BuildSmallModulusPointers1(const vector<SmallModulus> &in_mods, long *length, void **out_mods)
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
void* EncryptionParameters_ctor(int value) {
	EncryptionParameters* encparam_p = new EncryptionParameters(value);
        return (void*)encparam_p;
}

void EncPara_set_poly_modulus_degree(void* p,long poly_modulus_degree) {
  	EncryptionParameters* encparam_p = (EncryptionParameters*)p;
	encparam_p->set_poly_modulus_degree(poly_modulus_degree);
}

long EncPara_get_poly_modulus_degree(void* p) {
	EncryptionParameters* encparam_p = (EncryptionParameters*)p;
	return encparam_p->poly_modulus_degree();
}

void EncPara_set_coeff_modulus(void* p,int length,void** coeffArray) {
	EncryptionParameters* encparam_p = (EncryptionParameters*)p;
	SmallModulus* *coeff_array = reinterpret_cast<SmallModulus**>(coeffArray);
        vector<SmallModulus> coefficients(length);

    for (uint64_t i = 0; i < length; i++)
    {
        coefficients[i] = *coeff_array[i];
        cout << "##encpara set coeffmodulus" << coefficients[i].value() << endl;
    }

    try
    {
        encparam_p->set_coeff_modulus(coefficients);
    }
    catch (const invalid_argument&)
    {
	cout << "##error invalid argument" << endl;
    }
}

int Encpara_getScheme(void* p) {
    EncryptionParameters* encparam_p = (EncryptionParameters*)p;
    return (int)encparam_p->scheme();
}

void Encpara_get_coeff_modulus(void* p, void* len_p, void** coeffArray) {
    EncryptionParameters* encparam_p = (EncryptionParameters*)p;
    long* len = (long*)len_p;
    BuildSmallModulusPointers1(encparam_p->coeff_modulus(), len, coeffArray);
}

void Encpara_set_plain_modulus(void* p, void* mod) {
    EncryptionParameters* encparam_p = (EncryptionParameters*)p;
    SmallModulus* modulus = (SmallModulus*)mod;
    encparam_p->set_plain_modulus(*modulus);
}

void EncryptionParameters_get_params_id(void* p, void* block) {
    EncryptionParameters* encparam_p = (EncryptionParameters*)p;
    long* block_p = (long*)block;
    const seal::parms_id_type& paramsId = EncryptionParameters::EncryptionParametersPrivateHelper::parms_id(*encparam_p);
    //const seal::parms_id_type& paramsId = encparam_p->parms_id();
    std::copy_n(std::cbegin(paramsId), paramsId.size(), block_p); 
}

void* EncPara_get_plain_modulus(void* p) {
    EncryptionParameters* encparam_p = (EncryptionParameters*)p;
    const auto plainmodulus = &encparam_p->plain_modulus();
    return const_cast<SmallModulus*>(plainmodulus);
}

}
