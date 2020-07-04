package org.homobit.jseal;

import jnr.ffi.Pointer;

public class KeyGenerator {
    public Pointer self;
    public KeyGenerator(SealContext context) {
        Pointer context_p = context.self;
        this.self = CLibrary.INSTANCE.KeyGenerator_ctor(context_p);
    }

    public PublicKey getPublicKey() {
        Pointer p = CLibrary.INSTANCE.KeyGenerator_get_publicKey(self);
        return new PublicKey(p);
    }
    public SecretKey getSecretKey() {
        Pointer p = CLibrary.INSTANCE.KeyGenerator_get_secretKey(self);
        return new SecretKey(p);
    }
    public RelinKeys getRelinKeys() {
        Pointer p = CLibrary.INSTANCE.KeyGenerator_get_relinKeys(self);
        return new RelinKeys(p);
    }
    public GaloisKeys getGaloisKeys() {
        Pointer p = CLibrary.INSTANCE.KeyGenerator_get_galoisKeys(self);
        return new GaloisKeys(p);
    }
}
