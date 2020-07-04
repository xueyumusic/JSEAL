package org.homobit.jseal;

import jnr.ffi.Pointer;

public class Ciphertext {
    public Pointer self;
    public  Ciphertext() {
        self = CLibrary.INSTANCE.Ciphertext_ctor();
    }
    public Ciphertext(SealContext context) {
        self = CLibrary.INSTANCE.Ciphertext_ctor1(context.self);
    }

    public double getScale() {
        return CLibrary.INSTANCE.Ciphertext_get_scale(self);
    }
    public ParamsId getParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.Ciphertext_get_paramsId(self, paramsId.block);
        return paramsId;
    }
    public void setScale(double value) {
        CLibrary.INSTANCE.Ciphertext_set_scale(self, value);
    }
    public void reserve(long size_capacity) {
        CLibrary.INSTANCE.Ciphertext_reserve(self, size_capacity);

    }
    public int size() {
        return CLibrary.INSTANCE.Ciphertext_size(self);
    }
}
