package org.homobit.jseal;

public enum SchemeType {
    // No scheme set; cannot be used for encryption
    none(0x0),

    // Brakerski/Fan-Vercauteren scheme
    BFV(0x1),

    // Cheon-Kim-Kim-Song scheme
    CKKS(0x2);

    private int value;
    private SchemeType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

}
