package org.homobit.jseal;

import jnr.ffi.Pointer;

public class Evaluator {
    public Pointer self;
    public Evaluator(SealContext context) {
        self = CLibrary.INSTANCE.Evaluator_ctor(context.self);
    }

    public void square(Ciphertext encrypted, Ciphertext dest) {
        CLibrary.INSTANCE.Evaluator_square(self, encrypted.self, dest.self);
    }
    public void relinearize_inplace(Ciphertext encrypted, RelinKeys relinKeys) {
        CLibrary.INSTANCE.Evaluator_relinearize_inplace(self, encrypted.self, relinKeys.self);
    }
    public void rescale_to_next_inplace(Ciphertext encrypted) {
        CLibrary.INSTANCE.Evaluator_rescale_to_next_inplace(self, encrypted.self);
    }
    public void multiply_plain(Ciphertext encrypted, Plaintext plaintext, Ciphertext dest) {
        CLibrary.INSTANCE.Evaluator_multiply_plain(self, encrypted.self, plaintext.self, dest.self);
    }
    public void multiply_inplace(Ciphertext encrypted1, Ciphertext encrypted2) {
        CLibrary.INSTANCE.Evaluator_multiply_inplace(self, encrypted1.self, encrypted2.self);
    }
    public void multiply_plain_inplace(Ciphertext encrypted, Plaintext plain) {
        CLibrary.INSTANCE.Evaluator_multiply_plain_inplace(self, encrypted.self, plain.self);
    }
    public void multiply(Ciphertext encrypted1, Ciphertext encrypted2, Ciphertext destination) {
        CLibrary.INSTANCE.Evaluator_multiply(self, encrypted1.self, encrypted2.self, destination.self);
    }
    public void mod_switch_to_inplace(Ciphertext encrypted, ParamsId paramsId) {
        CLibrary.INSTANCE.Evaluator_mod_switch_to_inplace(self, encrypted.self, paramsId.block);
    }
    public void mod_switch_to_inplace(Plaintext plaintext, ParamsId paramsId) {
        CLibrary.INSTANCE.Evaluator_mod_switch_to_inplace_plain(self, plaintext.self, paramsId.block);
    }
    public void mod_switch_to_next_inplace(Ciphertext encrypted) {
        CLibrary.INSTANCE.Evaluator_mod_switch_to_next_inplace(self, encrypted.self);
    }
    public void add(Ciphertext encrypted1, Ciphertext encrypted2, Ciphertext dest) {
        CLibrary.INSTANCE.Evaluator_add(self, encrypted1.self, encrypted2.self, dest.self);
    }
    public void add_plain(Ciphertext encrypted, Plaintext plain, Ciphertext destination) {
        CLibrary.INSTANCE.Evaluator_add_plain(self, encrypted.self, plain.self, destination.self);
    }
    public void add_plain_inplace(Ciphertext encrypted, Plaintext plain) {
        CLibrary.INSTANCE.Evaluator_add_plain_inplace(self, encrypted.self, plain.self);
    }
    public void add_inplace(Ciphertext encrypted1, Ciphertext encrypted2) {
        CLibrary.INSTANCE.Evaluator_add_inplace(self, encrypted1.self, encrypted2.self);
    }
    public void square_inplace(Ciphertext encrypted) {
        CLibrary.INSTANCE.Evaluator_square_inplace(self, encrypted.self);
    }
    public void rotate_vector_inplace(Ciphertext encrypted, int steps, GaloisKeys galoisKeys) {
        CLibrary.INSTANCE.Evaluator_rotate_vector_inplace(self, encrypted.self, steps, galoisKeys.self);
    }
    public void complex_conjugate_inplace(Ciphertext encrypted, GaloisKeys galoisKeys) {
        CLibrary.INSTANCE.Evaluator_complex_conjugate_inplace(self, encrypted.self, galoisKeys.self);
    }
    public void rotate_rows_inplace(Ciphertext encrypted, int steps, GaloisKeys galoisKeys) {
        CLibrary.INSTANCE.Evaluator_rotate_rows_inplace(self, encrypted.self, steps, galoisKeys.self);
    }
    public void rotate_columns_inplace(Ciphertext encrypted, GaloisKeys galoisKeys) {
        CLibrary.INSTANCE.Evaluator_rotate_columns_inplace(self, encrypted.self, galoisKeys.self);
    }
    public void rotate_vector(Ciphertext encrypted, int steps, GaloisKeys galoisKeys, Ciphertext destination) {
        CLibrary.INSTANCE.Evaluator_rotate_vector(self, encrypted.self, steps, galoisKeys.self, destination.self);
    }
    public void negate(Ciphertext encrypted, Ciphertext destination) {
        CLibrary.INSTANCE.Evaluator_negate(self, encrypted.self, destination.self);
    }

}
