package org.homobit.jseal;

import jnr.ffi.Pointer;

public class IntegerEncoder {
    Pointer self;
    public IntegerEncoder(SealContext context) {
        self = CLibrary.INSTANCE.IntegerEncoder_ctor(context.self);
    }
    Plaintext encode(int value) {
        Plaintext result = new Plaintext();
        encode(value, result);
        return result;
    }
    Plaintext encode(long value) {
        Plaintext result = new Plaintext();
        encode(value, result);
        return result;
    }
    void encode(long value, Plaintext destination) {
        CLibrary.INSTANCE.IntegerEncoder_encode(self, value, destination.self);
    }
    int decode_int32(Plaintext plaintext) {
        return CLibrary.INSTANCE.IntegerEncoder_decode_int32(self, plaintext.self);
    }
}
