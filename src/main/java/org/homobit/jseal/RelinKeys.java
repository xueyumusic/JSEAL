package org.homobit.jseal;

import jnr.ffi.Pointer;

public class RelinKeys {
    public Pointer self;
    public RelinKeys(Pointer self) {
        this.self = self;
    }
    public ParamsId getParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.RelinKeys_get_paramsId(self, paramsId.block);
        return paramsId;
    }
}
