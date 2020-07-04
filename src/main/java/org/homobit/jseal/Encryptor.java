package org.homobit.jseal;

import jnr.ffi.Pointer;

public class Encryptor {
    public Pointer self;
    public Encryptor(SealContext context, PublicKey publicKey) {
        self = CLibrary.INSTANCE.Encryptor_ctor(context.self, publicKey.self);
    }

    public void encrypt(Plaintext plaintext, Ciphertext ciphertext) {
        CLibrary.INSTANCE.Encryptor_encrypt(self, plaintext.self, ciphertext.self);
    }
}
