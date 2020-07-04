package org.homobit.jseal;

public class ParamsId {
    private static final int uLongCount = 4;
    public static ParamsId zero = new ParamsId(new long[] { 0, 0, 0, 0 });
    public long[] block = new long[] { 0, 0, 0, 0 };

    public ParamsId() {

    }
    public ParamsId(ParamsId other) {
        copyId(this, other.block);
    }
    private ParamsId(long[] id) {
        copyId(this, id);
    }

    private static void copyId(ParamsId dest, long[] src) {
        int idx = 0;
        for (long l: src) {
            dest.block[idx++] = l;
        }
    }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        String strHex = "";
        for (int i = 0; i < uLongCount; i++) {
            byte[] bytes = Utils.GetBytes(block[i]);
            for (int b = bytes.length-1; b >= 0; b--) {
                //result.append()
                strHex = Integer.toHexString(bytes[b] & 0xFF);
                result.append((strHex.length() == 1) ? "0" + strHex : strHex);
            }
            if (i < uLongCount - 1) {
                result.append(" ");
            }
        }
        return  result.toString();
    }


    @Override
    public boolean equals(Object otherObj) {
        if (!(otherObj instanceof ParamsId)) {
            return false;
        }
        if (otherObj == null) {
            return false;
        }
        ParamsId other = (ParamsId)otherObj;
        for (int i = 0; i < uLongCount; i++) {
            if (block[i] != other.block[i]) {
                return false;
            }
        }
        return true;

    }

    @Override
    public int hashCode() {
        int hash_seed = 17;
        int hash_multiply = 23;
        int hash = hash_seed;

        for (int i = 0; i < uLongCount; i++) {

            long value = block[i];
            if (value != 0) {
                hash *= hash_multiply;
                hash += (int)value;
                value >>= 32;
                hash *= hash_multiply;
                hash += (int)value;
            }
        }
        return hash;
    }
}
