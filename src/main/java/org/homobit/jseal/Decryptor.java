package org.homobit.jseal;

import jnr.ffi.Pointer;

public class Decryptor {
    public Pointer self;

    public Decryptor(SealContext context, SecretKey secretKey) {
        self = CLibrary.INSTANCE.Decryptor_ctor(context.self, secretKey.self);
    }

    public void decrypt(Ciphertext ciphertext, Plaintext plaintext) {
        CLibrary.INSTANCE.Decryptor_decrypt(self, ciphertext.self, plaintext.self);
    }
    public int invariant_noise_budget(Ciphertext encrypted) {
        return CLibrary.INSTANCE.Decryptor_invariant_noise_budget(self, encrypted.self);
    }
}
