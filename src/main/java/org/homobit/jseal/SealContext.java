package org.homobit.jseal;

import java.io.IOException;
import java.math.BigDecimal;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

public class SealContext {
    public Pointer self;

    public SealContext(EncryptionParameters params) {
        this(params, true, SecLevelType.TC128);

    }
    public SealContext(EncryptionParameters params, boolean expandModChain) {
        this(params, expandModChain, SecLevelType.TC128);
    }
    public SealContext(EncryptionParameters params, boolean expandModChain, SecLevelType secLevel) {
        self = CLibrary.INSTANCE.SealContext_ctor(params.self, expandModChain, secLevel.getValue());
        System.out.println("##context ptr:" + self);
    }

    public ContextData getKeyContextData() {
        Pointer contextdata_p = CLibrary.INSTANCE.SealContext_getKeyContextData(self);
        return new ContextData(contextdata_p);
    }
    public ContextData getContextData(ParamsId paramsId) {
        Pointer contextdata_p = CLibrary.INSTANCE.SealContext_getContextData(self, paramsId.block);
        return new ContextData(contextdata_p);
    }
    public ContextData getFirstContextData() {
        Pointer contextdata_p = CLibrary.INSTANCE.SealContext_getFirstContextData(self);
        return new ContextData(contextdata_p);
    }
    public boolean usingKeySwitching() { return CLibrary.INSTANCE.SealContext_using_keyswitching(self); }
    public ParamsId getFirstParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.SealContext_get_first_params_id(self, paramsId.block);
        return paramsId;
    }
    public ParamsId getLastParamsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.SealContext_get_last_params_id(self, paramsId.block);
        return paramsId;
    }

    public class ContextData {
        public Pointer self;
        public ContextData(Pointer p) {
            self = p;
        }

        public long[] get_total_coeff_modulus() throws IOException {
            //Pointer len_p = ;
            Pointer len_p = Memory.allocate(Runtime.getRuntime(CLibrary.INSTANCE), 8);

            CLibrary.INSTANCE.SealContext_ContextData_get_total_coeff_modulus(self, len_p, null);
            System.out.println("##here3:"+len_p.getLong(0));
            long[] total_coeff_modulus = new long[(int)len_p.getLong(0)];
            CLibrary.INSTANCE.SealContext_ContextData_get_total_coeff_modulus(self, len_p, total_coeff_modulus);

            for (int i = 0; i < len_p.getLong(0); i++) {
                System.out.println("##context data coeff modulus:" + Utils.readUnsignedLong(total_coeff_modulus[i]));
            }

            return null;
        }

        public EncryptionParameters getParams() {
            Pointer param_p = CLibrary.INSTANCE.SealContext_ContextData_getParams(self);
            return new EncryptionParameters(param_p);
        }

        public long getChainIndex() {
            return CLibrary.INSTANCE.SealContext_ContextData_get_chain_index(self);
        }

        public EncryptionParameterQualifiers getQualifiers() {
            Pointer p = CLibrary.INSTANCE.SealContext_ContextData_getQualifiers(self);
            return new EncryptionParameterQualifiers(p);
        }

        public ParamsId getParamsId() {
            return getParams().getParmsId();
        }
        public ContextData getNextContextData() {
            Pointer p = CLibrary.INSTANCE.SealContext_ContextData_get_next_context_data(self);
            if (p == null) {
                return null;
            }
            System.out.println("##p:"+p);
            return new ContextData(p);
        }

    }
}
