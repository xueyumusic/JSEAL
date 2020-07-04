package org.homobit.jseal;

import jnr.ffi.Pointer;

public class Plaintext {
    public Pointer self;

    public Plaintext() {
        self = CLibrary.INSTANCE.Plaintext_ctor();
    }
    public Plaintext(long capacity, long coeffCount) {
        self = CLibrary.INSTANCE.Plaintext_ctor1(capacity, coeffCount);
    }
    public Plaintext(String hexPoly) {
        self = CLibrary.INSTANCE.Plaintext_ctor2(hexPoly);
    }
    public ParamsId getParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.Plaintext_get_paramsId(self, paramsId.block);
        return paramsId;
    }
    public double getScale() {
        return CLibrary.INSTANCE.Plaintext_get_scale(self);
    }

    @Override
    public String toString() {
        return CLibrary.INSTANCE.Plaintext_to_string(self);
    }
}
