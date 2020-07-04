package org.homobit.jseal;

import jnr.ffi.Pointer;

public class PublicKey {
    Pointer self;
    public  PublicKey(Pointer self) {
        this.self = self;
    }
    public ParamsId getParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.PublicKey_get_paramsId(self, paramsId.block);
        return paramsId;
    }
}
