package org.homobit.jseal;

public class PlainModulus {
    public static SmallModulus Batching(long poly_modulus_degree, int bit_size) {
        return CoeffModulus.create(poly_modulus_degree, new int[]{ bit_size }).get(0);
    }
}
