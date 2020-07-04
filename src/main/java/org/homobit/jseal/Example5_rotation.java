package org.homobit.jseal;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;

public class Example5_rotation {
    private void example_rotation_bfv() {
        System.out.println("Example: Rotation / Rotation in BFV");
        EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
        long poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        params.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20));

        SealContext context = new SealContext(params);
        // print content

        KeyGenerator keyGenerator = new KeyGenerator(context);
        PublicKey publicKey = keyGenerator.getPublicKey();
        SecretKey secretKey = keyGenerator.getSecretKey();
        RelinKeys relinKeys = keyGenerator.getRelinKeys();
        Encryptor encryptor = new Encryptor(context, publicKey);
        Evaluator evaluator = new Evaluator(context);
        Decryptor decryptor = new Decryptor(context, secretKey);

        BatchEncoder batchEncoder = new BatchEncoder(context);
        long slotCount = batchEncoder.slot_count();
        long rowSize = slotCount / 2;
        System.out.println("Plaintext matrix row size: " + rowSize);

        List<Long> pod_matrix = new ArrayList<Long>((int)slotCount);
        for (int i = 0; i < (int)slotCount; i++) {
            pod_matrix.add(0L);
        }
        pod_matrix.set(0, 0L);
        pod_matrix.set(1, 1L);
        pod_matrix.set(2, 2L);
        pod_matrix.set(3, 3L);
        pod_matrix.set((int)rowSize, 4L);
        pod_matrix.set((int)rowSize+1, 5L);
        pod_matrix.set((int)rowSize+2, 6L);
        pod_matrix.set((int)rowSize+3, 7L);
        System.out.println("Input plaintext matrix:");
        Utils.printMatrix(pod_matrix, (int)rowSize);
        //StringBuilder builder = new StringBuilder();
        //for (int i = 0; i < (int)slotCount; i++) {
        //    builder.append(pod_matrix.get(i));
        //    builder.append(" ");
        //}
        //System.out.println("##tag0:" + builder.toString());
        /*
        First we use BatchEncoder to encode the matrix into a plaintext. We encrypt
        the plaintext as usual.
        */
        Plaintext plain_matrix = new Plaintext();
        System.out.println("Encode and encrypt.");
        batchEncoder.encode(pod_matrix, plain_matrix);
        Ciphertext encrypted_matrix = new Ciphertext();
        encryptor.encrypt(plain_matrix, encrypted_matrix);
        System.out.println("    + Noise budget in fresh encryption: " + decryptor.invariant_noise_budget(encrypted_matrix) + " bits");

        /*
        Rotations require yet another type of special key called `Galois keys'. These
        are easily obtained from the KeyGenerator.
        */
        GaloisKeys galoisKeys = keyGenerator.getGaloisKeys();
        /*
        Now rotate both matrix rows 3 steps to the left, decrypt, decode, and print.
        */
        System.out.println("Rotate rows 3 steps left.");
        evaluator.rotate_rows_inplace(encrypted_matrix, 3, galoisKeys);
        Plaintext plain_result = new Plaintext();
        System.out.println("    + Noise budget after rotation: " + decryptor.invariant_noise_budget(encrypted_matrix) + " bits");
        System.out.println("    + Decrypt and decode ...... Correct.");
        decryptor.decrypt(encrypted_matrix, plain_result);
        pod_matrix.clear();
        batchEncoder.decode(plain_result, pod_matrix);
        Utils.printMatrix(pod_matrix, (int)rowSize);

        /*
        We can also rotate the columns, i.e., swap the rows.
        */
        System.out.println("Rotate columns.");
        evaluator.rotate_columns_inplace(encrypted_matrix, galoisKeys);
        System.out.println("    + Noise budget after rotation: " + decryptor.invariant_noise_budget(encrypted_matrix) + " bits");
        System.out.println("    + Decrypt and decode ...... Correct.");
        decryptor.decrypt(encrypted_matrix, plain_result);
        pod_matrix.clear();
        batchEncoder.decode(plain_result, pod_matrix);
        Utils.printMatrix(pod_matrix, (int)rowSize);

        /*
        Finally, we rotate the rows 4 steps to the right, decrypt, decode, and print.
        */
        System.out.println("Rotate rows 4 steps right.");
        evaluator.rotate_rows_inplace(encrypted_matrix, -4, galoisKeys);
        System.out.println("    + Noise budget after rotation: " + decryptor.invariant_noise_budget(encrypted_matrix) + " bits");
        System.out.println("    + Decrypt and decode ...... Correct.");
        decryptor.decrypt(encrypted_matrix, plain_result);
        pod_matrix.clear();
        batchEncoder.decode(plain_result, pod_matrix);
        Utils.printMatrix(pod_matrix, (int)rowSize);

    }
    private void example_rotation_ckks() {
        System.out.println("Example: Rotation / Rotation in CKKS");
        /*
        Rotations in the CKKS scheme work very similarly to rotations in BFV.
        */
        EncryptionParameters params = new EncryptionParameters(SchemeType.CKKS);
        long poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus.create(poly_modulus_degree, new int[]{40, 40, 40, 40, 40}));

        SealContext context = new SealContext(params);
        // print content

        KeyGenerator keyGenerator = new KeyGenerator(context);
        PublicKey publicKey = keyGenerator.getPublicKey();
        SecretKey secretKey = keyGenerator.getSecretKey();
        GaloisKeys galoisKeys = keyGenerator.getGaloisKeys();
        RelinKeys relinKeys = keyGenerator.getRelinKeys();
        Encryptor encryptor = new Encryptor(context, publicKey);
        Evaluator evaluator = new Evaluator(context);
        Decryptor decryptor = new Decryptor(context, secretKey);

        CKKSEncoder ckksEncoder = new CKKSEncoder(context);
        long slotCount = ckksEncoder.getSlotCount();
        System.out.println("Number of slots: " + slotCount);
        List<Double> input = new ArrayList<Double>((int)slotCount);
        double currPoint = 0.0;
        //double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
        double stepSize = 1.0 / ((double)slotCount - 1);
        for (int i = 0; i < slotCount; i++, currPoint += stepSize) {
            input.add(currPoint);
        }
        System.out.println("Input vector:");
        Utils.printVector(input, 3, 7);

        double scale = Math.pow(2.0, 50);
        System.out.println("Encode and encrypt.");
        Plaintext plain = new Plaintext();
        ckksEncoder.encode(input, scale, plain);
        Ciphertext encrypted = new Ciphertext();
        encryptor.encrypt(plain, encrypted);

        Ciphertext rotated = new Ciphertext();
        System.out.println("Rotate 2 steps left.");
        evaluator.rotate_vector(encrypted, 2, galoisKeys, rotated);
        System.out.println("    + Decrypt and decode ...... Correct.");
        decryptor.decrypt(rotated, plain);
        List<Double> result = new ArrayList<Double>();
        ckksEncoder.decode(plain, result);
        Utils.printVector(result, 3, 7);

        /*
        With the CKKS scheme it is also possible to evaluate a complex conjugation on
        a vector of encrypted complex numbers, using Evaluator::complex_conjugate.
        This is in fact a kind of rotation, and requires also Galois keys.
        */

    }
    public static void main(String[] args) {
        Example5_rotation example5_rotation = new Example5_rotation();
        example5_rotation.example_rotation_bfv();
        example5_rotation.example_rotation_ckks();
    }
}
