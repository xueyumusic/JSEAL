package org.homobit.jseal;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/*
In `1_bfv_basics.cpp' we showed how to perform a very simple computation using the
BFV scheme. The computation was performed modulo the plain_modulus parameter, and
utilized only one coefficient from a BFV plaintext polynomial. This approach has
two notable problems:

    (1) Practical applications typically use integer or real number arithmetic,
        not modular arithmetic;
    (2) We used only one coefficient of the plaintext polynomial. This is really
        wasteful, as the plaintext polynomial is large and will in any case be
        encrypted in its entirety.

For (1), one may ask why not just increase the plain_modulus parameter until no
overflow occurs, and the computations behave as in integer arithmetic. The problem
is that increasing plain_modulus increases noise budget consumption, and decreases
the initial noise budget too.

In these examples we will discuss other ways of laying out data into plaintext
elements (encoding) that allow more computations without data type overflow, and
can allow the full plaintext polynomial to be utilized.
*/
public class Example2_encoders {
    private void example_integer_encoder() {
        /*
        [IntegerEncoder] (For BFV scheme only)

        The IntegerEncoder encodes integers to BFV plaintext polynomials as follows.
        First, a binary expansion of the integer is computed. Next, a polynomial is
        created with the bits as coefficients. For example, the integer

            26 = 2^4 + 2^3 + 2^1

        is encoded as the polynomial 1x^4 + 1x^3 + 1x^1. Conversely, plaintext
        polynomials are decoded by evaluating them at x=2. For negative numbers the
        IntegerEncoder simply stores all coefficients as either 0 or -1, where -1 is
        represented by the unsigned integer plain_modulus - 1 in memory.

        Since encrypted computations operate on the polynomials rather than on the
        encoded integers themselves, the polynomial coefficients will grow in the
        course of such computations. For example, computing the sum of the encrypted
        encoded integer 26 with itself will result in an encrypted polynomial with
        larger coefficients: 2x^4 + 2x^3 + 2x^1. Squaring the encrypted encoded
        integer 26 results also in increased coefficients due to cross-terms, namely,

            (1x^4 + 1x^3 + 1x^1)^2 = 1x^8 + 2x^7 + 1x^6 + 2x^5 + 2x^4 + 1x^2;

        further computations will quickly increase the coefficients much more.
        Decoding will still work correctly in this case (evaluating the polynomial
        at x=2), but since the coefficients of plaintext polynomials are really
        integers modulo plain_modulus, implicit reduction modulo plain_modulus may
        yield unexpected results. For example, adding 1x^4 + 1x^3 + 1x^1 to itself
        plain_modulus many times will result in the constant polynomial 0, which is
        clearly not equal to 26 * plain_modulus. It can be difficult to predict when
        such overflow will take place especially when computing several sequential
        multiplications.

        The IntegerEncoder is easy to understand and use for simple computations,
        and can be a good tool to experiment with for users new to Microsoft SEAL.
        However, advanced users will probably prefer more efficient approaches,
        such as the BatchEncoder or the CKKSEncoder.
        */
        EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
        long poly_modulus_degree = 4096;
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));

        /*
        There is no hidden logic behind our choice of the plain_modulus. The only
        thing that matters is that the plaintext polynomial coefficients will not
        exceed this value at any point during our computation; otherwise the result
        will be incorrect.
        */
        params.set_plain_modulus(new SmallModulus(512L));
        SealContext context = new SealContext(params);


        KeyGenerator keyGenerator = new KeyGenerator(context);
        PublicKey publicKey = keyGenerator.getPublicKey();
        SecretKey secretKey = keyGenerator.getSecretKey();
        Encryptor encryptor = new Encryptor(context, publicKey);
        Decryptor decryptor = new Decryptor(context, secretKey);
        Evaluator evaluator = new Evaluator(context);

        /*
        We create an IntegerEncoder.
        */
        IntegerEncoder integerEncoder = new IntegerEncoder(context);
        /*
        First, we encode two integers as plaintext polynomials. Note that encoding
        is not encryption: at this point nothing is encrypted.
        */
        int value1 = 5;
        Plaintext plain1 = integerEncoder.encode(value1);
        System.out.println("Encode " + value1 + " as polynomial " + plain1.toString());

        int value2 = -7;
        Plaintext plain2 = integerEncoder.encode(value2);
        System.out.println("Encode " + value2 + " as polynomial " + plain2.toString());
        /*
        Now we can encrypt the plaintext polynomials.
        */
        Ciphertext encrypted1 = new Ciphertext();
        Ciphertext encrypted2 = new Ciphertext();
        System.out.println("Encrypt plain1 to encrypted1 and plain2 to encrypted2.");
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        System.out.println("    + Noise budget in encrypted1: " + decryptor.invariant_noise_budget(encrypted1) + " bits");
        System.out.println("    + Noise budget in encrypted2: " + decryptor.invariant_noise_budget(encrypted2) + " bits");

        /*
        As a simple example, we compute (-encrypted1 + encrypted2) * encrypted2.
        */
        encryptor.encrypt(plain2, encrypted2);
        Ciphertext encrypted_result = new Ciphertext();
        System.out.println("Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2.");
        evaluator.negate(encrypted1, encrypted_result);
        evaluator.add_inplace(encrypted_result, encrypted2);
        evaluator.multiply_inplace(encrypted_result, encrypted2);
        System.out.println("    + Noise budget in encrypted_result: " + decryptor.invariant_noise_budget(encrypted_result) + " bits");
        Plaintext plain_result = new Plaintext();
        System.out.println("Decrypt encrypted_result to plain_result.");
        decryptor.decrypt(encrypted_result, plain_result);

        /*
        Print the result plaintext polynomial. The coefficients are not even close
        to exceeding our plain_modulus, 512.
        */
        System.out.println("    + Plaintext polynomial: " + plain_result.toString());

        /*
        Decode to obtain an integer result.
        */
        System.out.println("Decode plain_result.");
        System.out.println("    + Decoded integer: " + integerEncoder.decode_int32(plain_result));
        System.out.println("...... Correct.");

    }
    private void example_batch_encoder() {
        /*
        [BatchEncoder] (For BFV scheme only)

        Let N denote the poly_modulus_degree and T denote the plain_modulus. Batching
        allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, with
        each element an integer modulo T. In the matrix view, encrypted operations act
        element-wise on encrypted matrices, allowing the user to obtain speeds-ups of
        several orders of magnitude in fully vectorizable computations. Thus, in all
        but the simplest computations, batching should be the preferred method to use
        with BFV, and when used properly will result in implementations outperforming
        anything done with the IntegerEncoder.
        */
        EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
        long poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));

        /*
        To enable batching, we need to set the plain_modulus to be a prime number
        congruent to 1 modulo 2*poly_modulus_degree. Microsoft SEAL provides a helper
        method for finding such a prime. In this example we create a 20-bit prime
        that supports batching.
        */
        params.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20));
        SealContext context = new SealContext(params);
        /*
        We can verify that batching is indeed enabled by looking at the encryption
        parameter qualifiers created by SEALContext.
        */
        EncryptionParameterQualifiers qualifiers = context.getFirstContextData().getQualifiers();
        System.out.println("Batching enabled: " + qualifiers.usingBatching());
        KeyGenerator keyGenerator = new KeyGenerator(context);
        PublicKey publicKey = keyGenerator.getPublicKey();
        SecretKey secretKey = keyGenerator.getSecretKey();
        RelinKeys relinKeys = keyGenerator.getRelinKeys();
        Encryptor encryptor = new Encryptor(context, publicKey);
        Evaluator evaluator = new Evaluator(context);
        Decryptor decryptor = new Decryptor(context, secretKey);

        /*
        Batching is done through an instance of the BatchEncoder class.
        */
        BatchEncoder batchEncoder = new BatchEncoder(context);
        /*
        The total number of batching `slots' equals the poly_modulus_degree, N, and
        these slots are organized into 2-by-(N/2) matrices that can be encrypted and
        computed on. Each slot contains an integer modulo plain_modulus.
        */
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

        /*
        First we use BatchEncoder to encode the matrix into a plaintext polynomial.
        */
        Plaintext plain_matrix = new Plaintext();
        System.out.println("Encode plaintext matrix:");
        batchEncoder.encode(pod_matrix, plain_matrix);
        /*
        We can instantly decode to verify correctness of the encoding. Note that no
        encryption or decryption has yet taken place.
        */
        List<Long> pod_result = new ArrayList<>();
        System.out.println("    + Decode plaintext matrix ...... Correct.");
        batchEncoder.decode(plain_matrix, pod_result);
        Utils.printMatrix(pod_result, (int)rowSize);

        /*
        Next we encrypt the encoded plaintext.
        */
        Ciphertext encrypted_matrix = new Ciphertext();
        System.out.println("Encrypt plain_matrix to encrypted_matrix.");
        encryptor.encrypt(plain_matrix, encrypted_matrix);
        System.out.println("    + Noise budget in encrypted_matrix: " + decryptor.invariant_noise_budget(encrypted_matrix) + " bits");

        /*
        Operating on the ciphertext results in homomorphic operations being performed
        simultaneously in all 8192 slots (matrix elements). To illustrate this, we
        form another plaintext matrix

            [ 1,  2,  1,  2,  1,  2, ..., 2 ]
            [ 1,  2,  1,  2,  1,  2, ..., 2 ]

        and encode it into a plaintext.
        */
        List<Long> pod_matrix2 = new ArrayList<>();
        for (long i = 0; i < slotCount; i++) {
            pod_matrix2.add(( i % 2) + 1);
        }
        Plaintext plain_matrix2 = new Plaintext();
        batchEncoder.encode(pod_matrix2, plain_matrix2);
        System.out.println("Second input plaintext matrix:");
        Utils.printMatrix(pod_matrix2, (int)rowSize);

        /*
        We now add the second (plaintext) matrix to the encrypted matrix, and square
        the sum.
        */
        System.out.println("Sum, square, and relinearize.");
        evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
        evaluator.square_inplace(encrypted_matrix);
        evaluator.relinearize_inplace(encrypted_matrix, relinKeys);

        /*
        How much noise budget do we have left?
        */
        System.out.println("    + Noise budget in result: " + decryptor.invariant_noise_budget(encrypted_matrix) + " bits");
        /*
        We decrypt and decompose the plaintext to recover the result as a matrix.
        */
        Plaintext plain_result = new Plaintext();
        System.out.println("Decrypt and decode result.");
        decryptor.decrypt(encrypted_matrix, plain_result);
        pod_result.clear();
        batchEncoder.decode(plain_result, pod_result);
        System.out.println("    + Result plaintext matrix ...... Correct.");
        Utils.printMatrix(pod_result, (int)rowSize);
        /*
        Batching allows us to efficiently use the full plaintext polynomial when the
        desired encrypted computation is highly parallelizable. However, it has not
        solved the other problem mentioned in the beginning of this file: each slot
        holds only an integer modulo plain_modulus, and unless plain_modulus is very
        large, we can quickly encounter data type overflow and get unexpected results
        when integer computations are desired. Note that overflow cannot be detected
        in encrypted form. The CKKS scheme (and the CKKSEncoder) addresses the data
        type overflow issue, but at the cost of yielding only approximate results.
        */
    }
    public void example_ckks_encoder() {
        /*
        [CKKSEncoder] (For CKKS scheme only)

        In this example we demonstrate the Cheon-Kim-Kim-Song (CKKS) scheme for
        computing on encrypted real or complex numbers. We start by creating
        encryption parameters for the CKKS scheme. There are two important
        differences compared to the BFV scheme:

            (1) CKKS does not use the plain_modulus encryption parameter;
            (2) Selecting the coeff_modulus in a specific way can be very important
                when using the CKKS scheme. We will explain this further in the file
                `ckks_basics.cpp'. In this example we use CoeffModulus::Create to
                generate 5 40-bit prime numbers.
        */
        EncryptionParameters params = new EncryptionParameters(SchemeType.CKKS);
        long poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus.create(poly_modulus_degree, new int[]{ 40, 40, 40, 40, 40 }));
        /*
        We create the SEALContext as usual and print the parameters.
        */
        SealContext context = new SealContext(params);
        /*
        Keys are created the same way as for the BFV scheme.
        */
        KeyGenerator keyGenerator = new KeyGenerator(context);
        PublicKey publicKey = keyGenerator.getPublicKey();
        SecretKey secretKey = keyGenerator.getSecretKey();
        RelinKeys relinKeys = keyGenerator.getRelinKeys();
        /*
        We also set up an Encryptor, Evaluator, and Decryptor as usual.
        */
        Encryptor encryptor = new Encryptor(context, publicKey);
        Evaluator evaluator = new Evaluator(context);
        Decryptor decryptor = new Decryptor(context, secretKey);
        /*
        To create CKKS plaintexts we need a special encoder: there is no other way
        to create them. The IntegerEncoder and BatchEncoder cannot be used with the
        CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
        Plaintext objects, which can subsequently be encrypted. At a high level this
        looks a lot like what BatchEncoder does for the BFV scheme, but the theory
        behind it is completely different.
        */
        CKKSEncoder ckksEncoder= new CKKSEncoder(context);
        /*
        In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes
        one real or complex number. This should be contrasted with BatchEncoder in
        the BFV scheme, where the number of slots is equal to poly_modulus_degree
        and they are arranged into a matrix with two rows.
        */
        long slotCount = ckksEncoder.getSlotCount();
        System.out.println("Number of slots: " + slotCount);
        /*
        We create a small vector to encode; the CKKSEncoder will implicitly pad it
        with zeros to full size (poly_modulus_degree / 2) when encoding.
        */
        Double[] tmpdarr = new Double[]{ 0.0, 1.1, 2.2, 3.3 };
        List<Double> input = new ArrayList<Double>(Arrays.asList(tmpdarr));
        System.out.println("Input vector: ");
        Utils.printVector(input);
        /*
        Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
        will be scaled up by the parameter `scale'. This is necessary since even in
        the CKKS scheme the plaintext elements are fundamentally polynomials with
        integer coefficients. It is instructive to think of the scale as determining
        the bit-precision of the encoding; naturally it will affect the precision of
        the result.

        In CKKS the message is stored modulo coeff_modulus (in BFV it is stored modulo
        plain_modulus), so the scaled message must not get too close to the total size
        of coeff_modulus. In this case our coeff_modulus is quite large (200 bits) so
        we have little to worry about in this regard. For this simple example a 30-bit
        scale is more than enough.
        */
        Plaintext plain = new Plaintext();
        double scale = Math.pow(2.0, 30);
        System.out.println("Encode input vector.");
        ckksEncoder.encode(input, scale, plain);
        /*
        We can instantly decode to check the correctness of encoding.
        */
        List<Double> output = new ArrayList<>();
        System.out.println("    + Decode input vector ...... Correct.");
        ckksEncoder.decode(plain, output);
        Utils.printVector(output);
        /*
        The vector is encrypted the same was as in BFV.
        */
        Ciphertext encrypted = new Ciphertext();
        System.out.println("Encrypt input vector, square, and relinearize.");
        encryptor.encrypt(plain, encrypted);
        /*
        Basic operations on the ciphertexts are still easy to do. Here we square the
        ciphertext, decrypt, decode, and print the result. We note also that decoding
        returns a vector of full size (poly_modulus_degree / 2); this is because of
        the implicit zero-padding mentioned above.
        */
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, relinKeys);
        /*
        We notice that the scale in the result has increased. In fact, it is now the
        square of the original scale: 2^60.
        */
        System.out.println("    + Scale in squared input: " + encrypted.getScale() +
            "(" + Utils.log2(encrypted.getScale()) + " bits)");

        System.out.println("Decrypt and decode.");
        decryptor.decrypt(encrypted, plain);
        output.clear();
        ckksEncoder.decode(plain, output);
        System.out.println("    + Result vector ...... Correct.");
        Utils.printVector(output);
        /*
        The CKKS scheme allows the scale to be reduced between encrypted computations.
        This is a fundamental and critical feature that makes CKKS very powerful and
        flexible. We will discuss it in great detail in `3_levels.cpp' and later in
        `4_ckks_basics.cpp'.
        */



    }

    public static void main(String[] args) {
        Example2_encoders example2_encoders = new Example2_encoders();
        example2_encoders.example_integer_encoder();
        example2_encoders.example_batch_encoder();
        example2_encoders.example_ckks_encoder();
    }
}
