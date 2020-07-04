package org.homobit.jseal;

import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.time.StopWatch;

public class Example6_performance {
    private void CKKSPerformanceTest(SealContext context) {
        StopWatch watch = new StopWatch();
        EncryptionParameters params = context.getFirstContextData().getParams();
        long poly_modulus_degree = params.get_poly_modulus_degree();
        KeyGenerator keygen = new KeyGenerator(context);
        SecretKey secretKey = keygen.getSecretKey();
        PublicKey publicKey = keygen.getPublicKey();

        RelinKeys relinKeys = null;
        GaloisKeys galoisKeys = null;

        if (context.usingKeySwitching()) {
            System.out.println("Generating relinearization keys:");
            //long begin = System.nanoTime();
            //Instant start = Instant.now();

            watch.start();
            relinKeys = keygen.getRelinKeys();
            galoisKeys = keygen.getGaloisKeys();
            //System.out.println("Done " + (System.nanoTime()-begin) + " microseconds");
            watch.stop();
            System.out.println("Done " + watch.getTime(TimeUnit.MICROSECONDS) + " microseconds");
            //System.out.println("Done " + (Duration.between(start, Instant.now()).toMillis()) + " microseconds");
            System.out.println("##quali:" + context.getFirstContextData().getQualifiers().usingBatching()+":"
                +context.getFirstContextData().getQualifiers().secLevel());

            watch.reset();
            watch.start();
            keygen.getGaloisKeys();
            watch.stop();
            System.out.println("galois key gen Done " + watch.getTime(TimeUnit.MICROSECONDS) + " microseconds");
        }

        Encryptor encryptor = new Encryptor(context, publicKey);
        Decryptor decryptor = new Decryptor(context, secretKey);
        Evaluator evaluator = new Evaluator(context);
        CKKSEncoder ckksEncoder = new CKKSEncoder(context);

        /*
        How many times to run the test?
        */
        long count = 10;

        /*
        Populate a vector of floating-point values to batch.
        */
        List<Double> podVector = new ArrayList<>();
        for (int i = 0; i < ckksEncoder.getSlotCount(); i++) {
            podVector.add(1.001*i);
        }

        System.out.println("Running tests");
        long time_encode_sum = 0;
        long time_decode_sum = 0;
        long time_encrypt_sum = 0;
        long time_decrypt_sum = 0;
        long time_add_sum = 0;
        long time_multiply_sum = 0;
        long time_multiply_plain_sum = 0;
        long time_square_sum = 0;
        long time_relinearize_sum = 0;
        long time_rescale_sum = 0;
        long time_rotate_one_step_sum = 0;
        long time_rotate_random_sum = 0;
        long time_conjugate_sum = 0;

        for (long i = 0; i < count; i++) {
            /*
            [Encoding]
            For scale we use the square root of the last coeff_modulus prime
            from parms.
            */
            Plaintext plain = new Plaintext(params.get_poly_modulus_degree()*params.get_coeff_modulus().size(), 0);
            List<SmallModulus> coeffModulus = params.get_coeff_modulus();
            double scale = Math.sqrt(coeffModulus.get(coeffModulus.size()-1).getValue());
            watch.reset();
            watch.start();
            ckksEncoder.encode(podVector, scale, plain);
            watch.stop();
            time_encode_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Decoding]
            */
            List<Double> podVector2 = new ArrayList<Double>((int)ckksEncoder.getSlotCount());
            watch.reset();
            watch.start();
            ckksEncoder.decode(plain, podVector2);
            watch.stop();
            time_decode_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Encryption]
            */
            Ciphertext encrypted = new Ciphertext(context);
            watch.reset();
            watch.start();
            encryptor.encrypt(plain, encrypted);
            watch.stop();
            time_encrypt_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Decryption]
            */
            Plaintext plain2 = new Plaintext(poly_modulus_degree, 0);
            watch.reset();
            watch.start();
            decryptor.decrypt(encrypted, plain2);
            watch.stop();
            time_decrypt_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Add]
            */
            Ciphertext encrypted1 = new Ciphertext(context);
            ckksEncoder.encode(i+1, plain);
            encryptor.encrypt(plain, encrypted1);
            Ciphertext encrypted2 = new Ciphertext(context);
            ckksEncoder.encode(i+1, plain2);
            encryptor.encrypt(plain2, encrypted2);
            watch.reset();
            watch.start();
            evaluator.add_inplace(encrypted1, encrypted1);
            evaluator.add_inplace(encrypted2, encrypted2);
            evaluator.add_inplace(encrypted1, encrypted2);
            watch.stop();
            time_add_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Multiply]
            */
            encrypted1.reserve(3);
            watch.reset();
            watch.start();
            evaluator.multiply_inplace(encrypted1, encrypted2);
            watch.stop();
            time_multiply_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Multiply Plain]
            */
            watch.reset();
            watch.start();
            evaluator.multiply_plain_inplace(encrypted2, plain);
            watch.stop();
            time_multiply_plain_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Square]
            */
            watch.reset();
            watch.start();
            evaluator.square_inplace(encrypted2);
            watch.stop();
            time_square_sum += watch.getTime(TimeUnit.MICROSECONDS);

            if (context.usingKeySwitching()) {
                watch.reset();
                watch.start();
                evaluator.relinearize_inplace(encrypted1, relinKeys);
                watch.stop();
                time_relinearize_sum += watch.getTime(TimeUnit.MICROSECONDS);


                watch.reset();
                watch.start();
                evaluator.rescale_to_next_inplace(encrypted1);
                watch.stop();
                time_rescale_sum += watch.getTime(TimeUnit.MICROSECONDS);

                watch.reset();
                watch.start();
                evaluator.rotate_vector_inplace(encrypted, 1, galoisKeys);
                evaluator.rotate_vector_inplace(encrypted, -1, galoisKeys);
                watch.stop();
                time_rotate_one_step_sum += watch.getTime(TimeUnit.MICROSECONDS);

                //random
                //

                watch.reset();
                watch.start();
                evaluator.complex_conjugate_inplace(encrypted, galoisKeys);
                watch.stop();
                time_conjugate_sum += watch.getTime(TimeUnit.MICROSECONDS);
            }

        }
        System.out.println("##time of encode:" +time_encode_sum+ " microseconds");
        System.out.println("##time of decode:" +time_decode_sum+ " microseconds");
        System.out.println("##time of encrypt:" +time_encrypt_sum+ " microseconds");
        System.out.println("##time of decrypt:" +time_decrypt_sum+ " microseconds");
        System.out.println("##time of add:" +time_add_sum+ " microseconds");
        System.out.println("##time of multiply:" +time_multiply_sum+ " microseconds");
        System.out.println("##time of multiply plain:" +time_multiply_plain_sum+ " microseconds");
        System.out.println("##time of square:" +time_square_sum+ " microseconds");
        System.out.println("##time of relinear:" +time_relinearize_sum+ " microseconds");
        System.out.println("##time of rescale:" +time_rescale_sum+ " microseconds");
        System.out.println("##time of rotate one step:" +time_rotate_one_step_sum+ " microseconds");
        System.out.println("##time of conjugate:" +time_conjugate_sum+ " microseconds");


    }
    private void BFVPerformanceTest(SealContext context) {
        StopWatch watch = new StopWatch();
        EncryptionParameters params = context.getFirstContextData().getParams();
        long poly_modulus_degree = params.get_poly_modulus_degree();
        SmallModulus plain_modulus = params.get_plain_modulus();
        System.out.println("##plain_modulus:" + plain_modulus);
        KeyGenerator keygen = new KeyGenerator(context);
        SecretKey secretKey = keygen.getSecretKey();
        PublicKey publicKey = keygen.getPublicKey();

        RelinKeys relinKeys = null;
        GaloisKeys galoisKeys = null;

        if (context.usingKeySwitching()) {
            System.out.println("Generating relinearization keys:");
            //long begin = System.nanoTime();
            //Instant start = Instant.now();

            watch.start();
            relinKeys = keygen.getRelinKeys();
            //galoisKeys = keygen.getGaloisKeys();
            //System.out.println("Done " + (System.nanoTime()-begin) + " microseconds");
            watch.stop();
            System.out.println("Done " + watch.getTime(TimeUnit.MICROSECONDS) + " microseconds");
            //System.out.println("Done " + (Duration.between(start, Instant.now()).toMillis()) + " microseconds");
            System.out.println("##quali:" + context.getFirstContextData().getQualifiers().usingBatching()+":"
                +context.getFirstContextData().getQualifiers().secLevel());

            watch.reset();
            watch.start();
            galoisKeys = keygen.getGaloisKeys();
            watch.stop();
            System.out.println("galois key gen Done " + watch.getTime(TimeUnit.MICROSECONDS) + " microseconds");
        }

        Encryptor encryptor = new Encryptor(context, publicKey);
        Decryptor decryptor = new Decryptor(context, secretKey);
        Evaluator evaluator = new Evaluator(context);
        BatchEncoder batchEncoder = new BatchEncoder(context);
        IntegerEncoder encoder = new IntegerEncoder(context);

        /*
        How many times to run the test?
        */
        long count = 10;
        long slot_count = batchEncoder.slot_count();
        Random random = new Random();
        /*
        Populate a vector of floating-point values to batch.
        */
        List<Long> podVector = new ArrayList<>();
        for (int i = 0; i < slot_count; i++) {
            long rdlong = random.nextLong();
            //System.out.println("##add long:" + rdlong);
            podVector.add(Math.abs(rdlong) % plain_modulus.getValue());
        }

        System.out.println("Running tests");
        long time_encode_sum = 0;
        long time_decode_sum = 0;
        long time_encrypt_sum = 0;
        long time_decrypt_sum = 0;
        long time_add_sum = 0;
        long time_multiply_sum = 0;
        long time_multiply_plain_sum = 0;
        long time_square_sum = 0;
        long time_relinearize_sum = 0;
        long time_rotate_one_step_sum = 0;
        long time_rotate_column_sum = 0;

        for (long i = 0; i < count; i++) {
            /*
            [Batching]
            There is nothing unusual here. We batch our random plaintext matrix
            into the polynomial. Note how the plaintext we create is of the exactly
            right size so unnecessary reallocations are avoided.
            */
            Plaintext plain = new Plaintext(params.get_poly_modulus_degree()*params.get_coeff_modulus().size(), 0);
            List<SmallModulus> coeffModulus = params.get_coeff_modulus();
            watch.reset();
            watch.start();
            batchEncoder.encode(podVector, plain);
            watch.stop();
            time_encode_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Unbatching]
            We unbatch what we just batched.
            */
            List<Long> podVector2 = new ArrayList<Long>((int)batchEncoder.slot_count());
            watch.reset();
            watch.start();
            batchEncoder.decode(plain, podVector2);
            watch.stop();
            time_decode_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Encryption]
            We make sure our ciphertext is already allocated and large enough
            to hold the encryption with these encryption parameters. We encrypt
            our random batched matrix here.
            */
            Ciphertext encrypted = new Ciphertext(context);
            watch.reset();
            watch.start();
            encryptor.encrypt(plain, encrypted);
            watch.stop();
            time_encrypt_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Decryption]
            We decrypt what we just encrypted.
            */
            Plaintext plain2 = new Plaintext(poly_modulus_degree, 0);
            watch.reset();
            watch.start();
            decryptor.decrypt(encrypted, plain2);
            watch.stop();
            time_decrypt_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Add]
            */
            Ciphertext encrypted1 = new Ciphertext(context);
            encryptor.encrypt(encoder.encode(i), encrypted1);
            Ciphertext encrypted2 = new Ciphertext(context);
            encryptor.encrypt(encoder.encode(i+1), encrypted2);
            watch.reset();
            watch.start();
            evaluator.add_inplace(encrypted1, encrypted1);
            evaluator.add_inplace(encrypted2, encrypted2);
            evaluator.add_inplace(encrypted1, encrypted2);
            watch.stop();
            time_add_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Multiply]
            We multiply two ciphertexts. Since the size of the result will be 3,
            and will overwrite the first argument, we reserve first enough memory
            to avoid reallocating during multiplication.
            */
            encrypted1.reserve(3);
            watch.reset();
            watch.start();
            evaluator.multiply_inplace(encrypted1, encrypted2);
            watch.stop();
            time_multiply_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Multiply Plain]
            We multiply a ciphertext with a random plaintext. Recall that
            multiply_plain does not change the size of the ciphertext so we use
            encrypted2 here.
            */
            watch.reset();
            watch.start();
            evaluator.multiply_plain_inplace(encrypted2, plain);
            watch.stop();
            time_multiply_plain_sum += watch.getTime(TimeUnit.MICROSECONDS);

            /*
            [Square]
            We continue to use encrypted2. Now we square it; this should be
            faster than generic homomorphic multiplication.
            */
            watch.reset();
            watch.start();
            evaluator.square_inplace(encrypted2);
            watch.stop();
            time_square_sum += watch.getTime(TimeUnit.MICROSECONDS);

            if (context.usingKeySwitching()) {
                /*
                [Relinearize]
                Time to get back to encrypted1. We now relinearize it back
                to size 2. Since the allocation is currently big enough to
                contain a ciphertext of size 3, no costly reallocations are
                needed in the process.
                */
                watch.reset();
                watch.start();
                evaluator.relinearize_inplace(encrypted1, relinKeys);
                watch.stop();
                time_relinearize_sum += watch.getTime(TimeUnit.MICROSECONDS);


                /*
                [Rotate Rows One Step]
                We rotate matrix rows by one step left and measure the time.
                */
                watch.reset();
                watch.start();
                evaluator.rotate_rows_inplace(encrypted, 1, galoisKeys);
                evaluator.rotate_rows_inplace(encrypted, -1, galoisKeys);
                watch.stop();
                time_rotate_one_step_sum += watch.getTime(TimeUnit.MICROSECONDS);

                //random
                //
                watch.reset();
                watch.start();
                evaluator.rotate_columns_inplace(encrypted, galoisKeys);
                watch.stop();
                time_rotate_column_sum += watch.getTime(TimeUnit.MICROSECONDS);
            }

        }
        System.out.println("##time of encode:" +time_encode_sum+ " microseconds");
        System.out.println("##time of decode:" +time_decode_sum+ " microseconds");
        System.out.println("##time of encrypt:" +time_encrypt_sum+ " microseconds");
        System.out.println("##time of decrypt:" +time_decrypt_sum+ " microseconds");
        System.out.println("##time of add:" +time_add_sum+ " microseconds");
        System.out.println("##time of multiply:" +time_multiply_sum+ " microseconds");
        System.out.println("##time of multiply plain:" +time_multiply_plain_sum+ " microseconds");
        System.out.println("##time of square:" +time_square_sum+ " microseconds");
        System.out.println("##time of relinear:" +time_relinearize_sum+ " microseconds");
        System.out.println("##time of rotate one step:" +time_rotate_one_step_sum+ " microseconds");
        System.out.println("##time of rotate column:" +time_rotate_column_sum+ " microseconds");

    }
    private void example_ckks_performance_default() {
        EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
        long poly_modulus_degree = 4096;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        //CoeffModulus.BFVDefault(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        CKKSPerformanceTest(new SealContext(parms));

        poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        CKKSPerformanceTest(new SealContext(parms));


        poly_modulus_degree = 16384;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        CKKSPerformanceTest(new SealContext(parms));


    }

    private void example_ckks_performance_custom() {
        long poly_modulus_degree = 0;
        System.out.println("Set poly_modulus_degree (1024, 2048, 4096, 8192, 16384, or 32768): ");
        Scanner scanner = new Scanner(System.in);
        poly_modulus_degree = scanner.nextLong();
        System.out.println("CKKS Performance Test with Degree: " + poly_modulus_degree);

        EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        CKKSPerformanceTest(new SealContext(parms));
    }
    private void example_bfv_performance_default() {
        EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
        long poly_modulus_degree = 4096;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(786433);
        BFVPerformanceTest(new SealContext(parms));

        poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(786433);
        BFVPerformanceTest(new SealContext(parms));

        poly_modulus_degree = 16384;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(786433);
        BFVPerformanceTest(new SealContext(parms));
    }
    private void example_bfv_performance_custom() {
        long poly_modulus_degree = 0;
        System.out.println("Set poly_modulus_degree (1024, 2048, 4096, 8192, 16384, or 32768): ");
        Scanner scanner = new Scanner(System.in);
        poly_modulus_degree = scanner.nextLong();
        System.out.println("CKKS Performance Test with Degree: " + poly_modulus_degree);

        EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree));
        if (poly_modulus_degree == 1024) {
            parms.set_plain_modulus(12289);
        } else {
            parms.set_plain_modulus(786433);
        }
        BFVPerformanceTest(new SealContext(parms));
    }
    public static void main(String[] args) {
        Example6_performance test = new Example6_performance();
        test.example_bfv_performance_default();
        test.example_bfv_performance_custom();
        test.example_ckks_performance_default();
        test.example_ckks_performance_custom();
    }
}
