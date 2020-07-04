package org.homobit.jseal;

public enum  SecLevelType {
    None(0),
    TC128(128),
    TC192(192),
    TC256(256);

    private int value;
    private SecLevelType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SecLevelType valueOf(int value) {
        switch (value) {
            case 0:
                return None;
            case 128:
                return TC128;
            case 192:
                return TC192;
            case 256:
                return TC256;
            default:
                return None;
        }
    }

}
