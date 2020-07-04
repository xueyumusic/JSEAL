package org.homobit.jseal;

import java.util.ArrayList;
import java.util.List;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

public class CoeffModulus {
    static public List<SmallModulus> create(long poly_modulus_degree, int[] bitSizes) {
        List<SmallModulus> result = null;
        int length = bitSizes.length;

        Pointer[] coeffArray = new Pointer[length];

        CLibrary.INSTANCE.CoeffModulus_create(poly_modulus_degree,length,bitSizes,coeffArray);
        result = new ArrayList<SmallModulus>(length);
        for(int i=0;i<coeffArray.length;i++) {
            System.out.println("##coeff point:"+coeffArray[i]);
            result.add(new SmallModulus(coeffArray[i]));
        }

        return result;
    }
    static public List<SmallModulus> BFVDefault(long poly_modulus_degree) {
        return BFVDefault(poly_modulus_degree, SecLevelType.TC128);
    }
    static public List<SmallModulus> BFVDefault(long poly_modulus_degree, SecLevelType sec_level) {
        List<SmallModulus> result = null;
        Pointer len_p = Memory.allocate(Runtime.getRuntime(CLibrary.INSTANCE), 8);
        CLibrary.INSTANCE.CoeffModulus_BFVDefault(poly_modulus_degree, sec_level.getValue(), len_p, null);

        int length = (int)len_p.getLong(0);
        System.out.println("##bfv default len:"+length);
        Pointer[] coeffArray = new Pointer[length];
        CLibrary.INSTANCE.CoeffModulus_BFVDefault(poly_modulus_degree, sec_level.getValue(), len_p, coeffArray);
        result = new ArrayList<SmallModulus>(length);
        for(int i=0;i<coeffArray.length;i++) {
            System.out.println("##coeff point:"+coeffArray[i]);
            result.add(new SmallModulus(coeffArray[i]));
        }

        return result;
    }

}
