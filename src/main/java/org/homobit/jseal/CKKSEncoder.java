package org.homobit.jseal;

import java.util.List;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

public class CKKSEncoder {
    public Pointer self;
    public CKKSEncoder(SealContext context) {
        self = CLibrary.INSTANCE.CKKSEncoder_ctor(context.self);
    }

    public long getSlotCount() {
        return CLibrary.INSTANCE.CKKSEncoder_get_slot_count(self);
    }

    public void encode(double value, double scale, Plaintext destination) {
        CLibrary.INSTANCE.CKKSEncoder_encode(self, value, scale, destination.self);
    }

    public void encode(List<Double> values, double scale, Plaintext destination) {
        //Double[] valueArr = values.toArray(new Double[0]);
        double[] valueArr = new double[values.size()];
        for (int i = 0; i < values.size(); i++) {
            valueArr[i] = values.get(i);
        }
        CLibrary.INSTANCE.CKKSEncoder_encode1(self, valueArr, valueArr.length, scale, destination.self);
    }

    public void encode(long value, Plaintext destination) {
        CLibrary.INSTANCE.CKKSEncoder_encode2(self, value, destination.self);
    }

    public void decode(Plaintext plain, List<Double> destination) {
        Pointer len_p = Memory.allocate(Runtime.getRuntime(CLibrary.INSTANCE), 8);
        CLibrary.INSTANCE.CKKSEncoder_decode(self, plain.self, len_p, null);
        double[] values = new double[(int)len_p.getLong(0)];
        CLibrary.INSTANCE.CKKSEncoder_decode(self, plain.self, len_p, values);
        for (int i = 0; i < values.length; i++) {
            destination.add(values[i]);
        }

    }
}
