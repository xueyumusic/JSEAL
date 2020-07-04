package org.homobit.jseal;

import jnr.ffi.Pointer;

public class SmallModulus {
    public Pointer self;
    SmallModulus(long value) {
        self = CLibrary.INSTANCE.SmallModulus_ctor(value);
    }

    SmallModulus(Pointer p) {
        self = p;
    }

    long getValue() {
        return CLibrary.INSTANCE.SmallModulus_getValue(self);
    }


}
