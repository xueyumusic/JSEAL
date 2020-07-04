package org.homobit.jseal;

import jnr.ffi.Pointer;

public class EncryptionParameterQualifiers {
    public Pointer self;

    public EncryptionParameterQualifiers(Pointer self) {
        this.self = self;
    }

    public boolean usingBatching() {
        return CLibrary.INSTANCE.EPQ_using_batching(self);
    }

    public SecLevelType secLevel() {
        int secLevel = CLibrary.INSTANCE.EPQ_sec_level(self);
        System.out.println("##secleve:"+secLevel);
        return SecLevelType.valueOf(secLevel);

    }

}
