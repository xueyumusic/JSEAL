package org.homobit.jseal;

import jnr.ffi.Pointer;

public class GaloisKeys {
    public Pointer self;
    public GaloisKeys(Pointer self) {
        this.self = self;
    }
    public ParamsId getParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.GaloisKeys_get_paramsId(self, paramsId.block);
        return paramsId;
    }
}
