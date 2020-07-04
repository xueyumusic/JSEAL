package org.homobit.jseal;

import java.util.ArrayList;
import java.util.List;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

public class EncryptionParameters {

    public Pointer self;
    public  EncryptionParameters() {
        self = CLibrary.INSTANCE.EncryptionParameters_ctor(SchemeType.none.getValue());
    }
    public EncryptionParameters(SchemeType scheme) {
        self = CLibrary.INSTANCE.EncryptionParameters_ctor(scheme.getValue());
    }
    public EncryptionParameters(Pointer p) {
        this.self = p;
    }

    public void set_poly_modulus_degree(long poly_modulus_degree) {
        CLibrary.INSTANCE.EncPara_set_poly_modulus_degree(self, poly_modulus_degree);
    }

    public long get_poly_modulus_degree() {
        return CLibrary.INSTANCE.EncPara_get_poly_modulus_degree(self);
    }

    public void set_coeff_modulus(List<SmallModulus> coeff_modulus) {
        int len = coeff_modulus.size();
        Pointer[] modpArr = new Pointer[len];

        for (int i = 0; i < len; i++) {
            modpArr[i] = coeff_modulus.get(i).self;
        }

        CLibrary.INSTANCE.EncPara_set_coeff_modulus(self, len, modpArr);

    }

    public List<SmallModulus> get_coeff_modulus() {
        Pointer len_p = Memory.allocate(Runtime.getRuntime(CLibrary.INSTANCE), 8);
        CLibrary.INSTANCE.Encpara_get_coeff_modulus(self, len_p, null);
        int length = (int)len_p.getLong(0);
        Pointer[] coeffArray = new Pointer[length];
        CLibrary.INSTANCE.Encpara_get_coeff_modulus(self, len_p, coeffArray);

        List<SmallModulus> result = new ArrayList<SmallModulus>();
        for(int i = 0; i < length; i++) {
            result.add(new SmallModulus(coeffArray[i]));
        }
        return result;
    }

    public int getScheme() {
        int scheme = CLibrary.INSTANCE.Encpara_getScheme(self);
        return scheme;
    }

    public void set_plain_modulus(SmallModulus plain_modulus) {
        CLibrary.INSTANCE.Encpara_set_plain_modulus(self, plain_modulus.self);
    }
    public void set_plain_modulus(long plain_modulus) {
        set_plain_modulus(new SmallModulus(plain_modulus));
    }
    public SmallModulus get_plain_modulus() {
        Pointer p = CLibrary.INSTANCE.EncPara_get_plain_modulus(self);
        return new SmallModulus(p);
    }

    ParamsId getParmsId() {
        ParamsId paramsId = new ParamsId();
        CLibrary.INSTANCE.EncryptionParameters_get_params_id(self, paramsId.block);
        return paramsId;
    }

}
