package org.homobit.jseal;

import java.security.cert.PolicyNode;

import com.kenai.jffi.Library;
import jnr.ffi.LibraryLoader;
import jnr.ffi.Pointer;
import jnr.ffi.types.size_t;

public interface CLibrary {
    CLibrary INSTANCE = LibraryLoader.create(CLibrary.class).load("sealjnr");
    Pointer EncryptionParameters_ctor(int value);
    void EncPara_set_poly_modulus_degree(Pointer p,long poly_modulus_degree);
    long EncPara_get_poly_modulus_degree(Pointer p);
    void EncPara_set_coeff_modulus(Pointer p, int len, Pointer[] modpArr);
    void Encpara_get_coeff_modulus(Pointer p, Pointer len_p, Pointer[] coeffArray);
    int Encpara_getScheme(Pointer p);
    void Encpara_set_plain_modulus(Pointer p, Pointer plain_modulus);
    Pointer EncPara_get_plain_modulus(Pointer p);
    void EncryptionParameters_get_params_id(Pointer p, long[] block);

    Pointer SmallModulus_ctor(long value);
    long SmallModulus_getValue(Pointer p);

    void CoeffModulus_create(long poly_modulus_degree, long length, int[] bitSizeArr, Pointer[] coeffArray);
    void CoeffModulus_BFVDefault(long poly_modulus_degree, int sec_level, Pointer len_p, Pointer[] coeffArray);

    Pointer SealContext_ctor(Pointer encParam, boolean expandModChain, int secLevel);
    Pointer SealContext_getKeyContextData(Pointer p);
    Pointer SealContext_getContextData(Pointer p, long[] block);
    Pointer SealContext_getFirstContextData(Pointer p);
    boolean SealContext_using_keyswitching(Pointer p);
    void SealContext_get_first_params_id(Pointer p, long[] block);
    void SealContext_get_last_params_id(Pointer p, long[] block);

    void SealContext_ContextData_get_total_coeff_modulus(Pointer data_p, Pointer len_p, long[] total_coeff_modulus_p);
    Pointer SealContext_ContextData_getParams(Pointer data_p);
    long SealContext_ContextData_get_chain_index(Pointer data_p);
    Pointer SealContext_ContextData_getQualifiers(Pointer data_p);
    Pointer SealContext_ContextData_get_next_context_data(Pointer data_p);

    Pointer KeyGenerator_ctor(Pointer context_p);
    Pointer KeyGenerator_get_publicKey(Pointer p);
    Pointer KeyGenerator_get_secretKey(Pointer p);
    Pointer KeyGenerator_get_relinKeys(Pointer p);
    Pointer KeyGenerator_get_galoisKeys(Pointer p);

    Pointer Encryptor_ctor(Pointer context, Pointer publicKey);
    void Encryptor_encrypt(Pointer p, Pointer plaintext, Pointer ciphertext);

    Pointer Decryptor_ctor(Pointer context, Pointer secretKey);
    Pointer Decryptor_decrypt(Pointer self, Pointer ciphertext, Pointer plaintext);
    int Decryptor_invariant_noise_budget(Pointer self, Pointer encrypted);

    Pointer Evaluator_ctor(Pointer context);
    void Evaluator_square(Pointer self, Pointer encrypted, Pointer dest);
    void Evaluator_square_inplace(Pointer self, Pointer encrypted);
    void Evaluator_relinearize_inplace(Pointer self, Pointer encrypted, Pointer relinKeys);
    void Evaluator_rescale_to_next_inplace(Pointer self, Pointer encrypted);
    void Evaluator_multiply_plain(Pointer self, Pointer encrypted, Pointer plaintext, Pointer dest);
    void Evaluator_multiply_inplace(Pointer self, Pointer encrypted1, Pointer encrypted2);
    void Evaluator_multiply_plain_inplace(Pointer self, Pointer encrypted, Pointer plaintext);
    void Evaluator_multiply(Pointer self, Pointer encrypted1, Pointer encrypted2, Pointer destination);
    void Evaluator_mod_switch_to_inplace(Pointer self, Pointer encrypted, long[] block);
    void Evaluator_mod_switch_to_inplace_plain(Pointer self, Pointer plain, long[] block);
    void Evaluator_mod_switch_to_next_inplace(Pointer self, Pointer encrypted);
    void Evaluator_add(Pointer self, Pointer encrypted1, Pointer encrypted2, Pointer dest);
    void Evaluator_add_plain(Pointer self, Pointer encrypted, Pointer plain, Pointer destination);
    void Evaluator_add_plain_inplace(Pointer self, Pointer encrypted, Pointer plain);
    void Evaluator_add_inplace(Pointer self, Pointer encrypted1, Pointer encrypted2);
    void Evaluator_rotate_vector_inplace(Pointer self, Pointer encrypted, int steps, Pointer galoisKeys);
    void Evaluator_complex_conjugate_inplace(Pointer self, Pointer encrypted, Pointer galoisKeys);
    void Evaluator_rotate_rows_inplace(Pointer self, Pointer encrypted, int steps, Pointer galoisKeys);
    void Evaluator_rotate_columns_inplace(Pointer self, Pointer encrypted, Pointer galoisKeys);
    void Evaluator_rotate_vector(Pointer self, Pointer encrypted, int steps, Pointer galoisKeys, Pointer destination);
    void Evaluator_negate(Pointer self, Pointer encrypted, Pointer destination);

    Pointer CKKSEncoder_ctor(Pointer context);
    @size_t
    long CKKSEncoder_get_slot_count(Pointer p);
    void CKKSEncoder_encode(Pointer p, double value, double scale, Pointer destination);
    void CKKSEncoder_encode1(Pointer p, double[] values, int size, double scale, Pointer destination);
    void CKKSEncoder_encode2(Pointer p, long value, Pointer destination);
    void CKKSEncoder_decode(Pointer p, Pointer plaintext, Pointer len_p, double[] destination);

    Pointer Plaintext_ctor();
    Pointer Plaintext_ctor1(long capacity, long coeffCount);
    Pointer Plaintext_ctor2(String hexPoly);
    void Plaintext_get_paramsId(Pointer p, long[] block);
    double Plaintext_get_scale(Pointer p);
    String Plaintext_to_string(Pointer p);


    Pointer Ciphertext_ctor();
    Pointer Ciphertext_ctor1(Pointer p);
    double Ciphertext_get_scale(Pointer p);
    void Ciphertext_get_paramsId(Pointer p, long[] block);
    void Ciphertext_set_scale(Pointer p, double value);
    void Ciphertext_reserve(Pointer p, long sizeCapacity);
    int Ciphertext_size(Pointer p);

    boolean EPQ_using_batching(Pointer p);
    int EPQ_sec_level(Pointer p);

    void PublicKey_get_paramsId(Pointer p, long[] block);

    void SecretKey_get_paramsId(Pointer p, long[] block);

    void RelinKeys_get_paramsId(Pointer p, long[] block);

    void GaloisKeys_get_paramsId(Pointer p, long[] block);

    Pointer BatchEncoder_ctor(Pointer p);
    long BatchEncoder_slot_count(Pointer p);
    void BatchEncoder_encode(Pointer p, long[] values, int size, Pointer destination);
    void BatchEncoder_decode(Pointer p, Pointer plaintext, Pointer len_p, long[] destination);

    Pointer IntegerEncoder_ctor(Pointer p);
    void IntegerEncoder_encode(Pointer p, long value, Pointer destination);
    int IntegerEncoder_decode_int32(Pointer p, Pointer plain);

}
