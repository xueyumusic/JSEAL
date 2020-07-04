package org.homobit.jseal;

import jnr.ffi.Pointer;

public class SecretKey {
    public Pointer self;
    public SecretKey(Pointer self) {
        this.self = self;
    }
    public ParamsId getParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.SecretKey_get_paramsId(self, paramsId.block);
        return paramsId;
    }
}
