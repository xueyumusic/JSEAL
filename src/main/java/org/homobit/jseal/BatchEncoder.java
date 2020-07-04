package org.homobit.jseal;

import java.util.List;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

public class BatchEncoder {
    Pointer self;
    public BatchEncoder(SealContext context) {
        self = CLibrary.INSTANCE.BatchEncoder_ctor(context.self);
    }
    public long slot_count() {
        return CLibrary.INSTANCE.BatchEncoder_slot_count(self);
    }
    public void encode(List<Long> values, Plaintext destination) {
        long[] valueArr = new long[values.size()];
        for (int i = 0; i < values.size(); i++) {
            valueArr[i] = values.get(i); /// TODO: long to unsigned long
        }
        CLibrary.INSTANCE.BatchEncoder_encode(self, valueArr, valueArr.length, destination.self);
    }

    public void decode(Plaintext plain, List<Long> destination) {
        Pointer len_p = Memory.allocate(Runtime.getRuntime(CLibrary.INSTANCE), 8);
        CLibrary.INSTANCE.BatchEncoder_decode(self, plain.self, len_p, null);
        long[] values = new long[(int)len_p.getLong(0)];
        CLibrary.INSTANCE.BatchEncoder_decode(self, plain.self, len_p, values);
        for (int i = 0; i < values.length; i++) {
            destination.add(values[i]);
        }

    }
}
