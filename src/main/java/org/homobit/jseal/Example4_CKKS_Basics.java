package org.homobit.jseal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Example4_CKKS_Basics {
    public static  void main(String[] args) throws IOException {
        EncryptionParameters enc_param = new EncryptionParameters(SchemeType.CKKS);
        int poly_modulus_degree = 8192;
        enc_param.set_poly_modulus_degree(poly_modulus_degree);
        long res = enc_param.get_poly_modulus_degree();
        System.out.println(("##res:"+res));

        int[] marr = {60, 40, 40, 60};
        List<SmallModulus> sms = CoeffModulus.create(poly_modulus_degree, marr);
        for (SmallModulus sm: sms) {
            System.out.println("##here1:"+sm.getValue());
        }

        enc_param.set_coeff_modulus(sms);

        SealContext context = new SealContext(enc_param);
        SealContext.ContextData contextData = context.getKeyContextData();
        System.out.println("##contextdata ptr:"+contextData);
        contextData.get_total_coeff_modulus();

        System.out.println("##injava contextdata scheme:" + contextData.getParams().getScheme());
        KeyGenerator keygen = new KeyGenerator(context);
        PublicKey pubkey = keygen.getPublicKey();
        System.out.println("##pubkey:"+pubkey.self);
        SecretKey secretKey = keygen.getSecretKey();
        System.out.println("##secretkey:"+secretKey.self);
        RelinKeys relinKeys = keygen.getRelinKeys();
        System.out.println("##relinKeys:"+relinKeys.self);

        Encryptor encryptor = new Encryptor(context, pubkey);
        System.out.println("##encryptor:"+encryptor.self);
        Decryptor decryptor = new Decryptor(context, secretKey);
        System.out.println("##encryptor:"+decryptor.self);
        Evaluator evaluator = new Evaluator(context);
        System.out.println("##evaluator:"+evaluator.self);

        CKKSEncoder encoder = new CKKSEncoder(context);
        System.out.println("##ckksencoder:"+encoder.self);
        long slotCount = encoder.getSlotCount();
        System.out.println("##slotcount:"+slotCount);

        //List<double> input = new List<double>((int)slotCount);
        //double currPoint = 0, stepSize = 1.0 / (slotCount - 1);
        //for (ulong i = 0; i < slotCount; i++, currPoint += stepSize)
        //{
        //    input.Add(currPoint);
        //}
        //Console.WriteLine("Input vector:");
        //Utilities.PrintVector(input, 3, 7);

        List<Double> input = new ArrayList<Double>((int)slotCount);
        double currPoint = 0, stepSize = 1.0 / (slotCount - 1);
        for (int i = 0; i < slotCount; i++, currPoint += stepSize) {
            input.add(currPoint);
        }
        System.out.println("##Input vector");
        for (int i = 0; i < input.size(); i++) {
            System.out.println("##input vec " + i + ":" + input.get(i));
        }

        System.out.println("Evaluating polynomial PI*x^3 + 0.4x + 1 ...");
        Plaintext plainCoeff3 = new Plaintext(),
            plainCoeff1 = new Plaintext(),
            plainCoeff0 = new Plaintext();
        double scale = Math.pow(2.0, 40);
        encoder.encode(3.14159265, scale, plainCoeff3);
        encoder.encode(0.4, scale, plainCoeff1);
        encoder.encode(1.0, scale, plainCoeff0);

        /*
            Plaintext xPlain = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Encode input vectors.");
            encoder.Encode(input, scale, xPlain);
            Ciphertext x1Encrypted = new Ciphertext();
            encryptor.Encrypt(xPlain, x1Encrypted);
         */
        Plaintext xPlain = new Plaintext();
        encoder.encode(input, scale, xPlain);
        Ciphertext x1Encrypted = new Ciphertext();
        encryptor.encrypt(xPlain, x1Encrypted);

        /*
        To compute x^3 we first compute x^2 and relinearize. However, the scale has
        now grown to 2^80.
        */

        Ciphertext x3Encrypted = new Ciphertext();
        evaluator.square(x1Encrypted, x3Encrypted);
        evaluator.relinearize_inplace(x3Encrypted, relinKeys);
        System.out.println("##scalae of x^2 before scala:"+Math.log(x3Encrypted.getScale())/Math.log(2));

        /*
        Now rescale; in addition to a modulus switch, the scale is reduced down by
        a factor equal to the prime that was switched away (40-bit prime). Hence, the
        new scale should be close to 2^40. Note, however, that the scale is not equal
        to 2^40: this is because the 40-bit prime is only close to 2^40.
        */
        evaluator.rescale_to_next_inplace(x3Encrypted);
        System.out.println("##scalae of x^2 after scala:"+Math.log(x3Encrypted.getScale())/Math.log(2));

        /*
        Now x3_encrypted is at a different level than x1_encrypted, which prevents us
        from multiplying them to compute x^3. We could simply switch x1_encrypted to
        the next parameters in the modulus switching chain. However, since we still
        need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
        first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
        PI*x and rescale it back from scale 2^80 to something close to 2^40.
        */

        Ciphertext x1EncryptedCoeff3 = new Ciphertext();
        evaluator.multiply_plain(x1Encrypted, plainCoeff3, x1EncryptedCoeff3);
        System.out.println("##Scale of PI*x before scala 1:"+Math.log(x1EncryptedCoeff3.getScale())/Math.log(2));
        evaluator.rescale_to_next_inplace(x1EncryptedCoeff3);
        System.out.println("##Scale of PI*x after scala 1:"+Math.log(x1EncryptedCoeff3.getScale())/Math.log(2));

        /*
        Since x3Encrypted and x1EncryptedCoeff3 have the same exact scale and use
        the same encryption parameters, we can multiply them together. We write the
        result to x3Encrypted, relinearize, and rescale. Note that again the scale
        is something close to 2^40, but not exactly 2^40 due to yet another scaling
        by a prime. We are down to the last level in the modulus switching chain.
        */
        System.out.println("Compute, relinearize, and rescale (PI*x)*x^2.");
        evaluator.multiply_inplace(x3Encrypted, x1EncryptedCoeff3);
        evaluator.relinearize_inplace(x3Encrypted, relinKeys);
        System.out.println("##Scale of PI*x^3 before rescale 1:"+Math.log(x3Encrypted.getScale())/Math.log(2));
        evaluator.rescale_to_next_inplace(x3Encrypted);
        System.out.println("##Scale of PI*x^3 before rescale 1:"+Math.log(x3Encrypted.getScale())/Math.log(2));


        /*
        Next we compute the degree one term. All this requires is one multiply_plain
        with plain_coeff1. We overwrite x1_encrypted with the result.
        */
        System.out.println("Compute and rescale 0.4*x.");
        evaluator.multiply_plain_inplace(x1Encrypted, plainCoeff1);
        System.out.println("##Scale of 0.4*x before rescale 1:"+Math.log(x1Encrypted.getScale())/Math.log(2));
        evaluator.rescale_to_next_inplace(x1Encrypted);
        System.out.println("##Scale of 0.4*x after rescale 1:"+Math.log(x1Encrypted.getScale())/Math.log(2));

        /*
        Now we would hope to compute the sum of all three terms. However, there is
        a serious problem: the encryption parameters used by all three terms are
        different due to modulus switching from rescaling.

        Encrypted addition and subtraction require that the scales of the inputs are
        the same, and also that the encryption parameters (parms_id) match. If there
        is a mismatch, Evaluator will throw an exception.
        */
        System.out.println("Parameters used by all three terms are different.");
        ParamsId paramsId = x3Encrypted.getParamsId();
        System.out.println("##x3Encrypted paramsId:"+paramsId);
        System.out.println("Modulus chain index for x3_encrypted:" +
            context.getContextData(paramsId).getChainIndex());
        System.out.println("Modulus chain index for x1_encrypted:" +
            context.getContextData(x1Encrypted.getParamsId()).getChainIndex());
        System.out.println("Modulus chain index for plain_coeff0:" +
            context.getContextData(plainCoeff0.getParamsId()).getChainIndex());

        /*
            Let us carefully consider what the scales are at this point. We denote the
            primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as
            the special modulus and is not involved in rescalings. After the computations
            above the scales in ciphertexts are:

                - Product x^2 has scale 2^80 and is at level 2;
                - Product PI*x has scale 2^80 and is at level 2;
                - We rescaled both down to scale 2^80/P2 and level 1;
                - Product PI*x^3 has scale (2^80/P_2)^2;
                - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;
                - Product 0.4*x has scale 2^80;
                - We rescaled it down to scale 2^80/P_2 and level 1;
                - The contant term 1 has scale 2^40 and is at level 2.

            Although the scales of all three terms are approximately 2^40, their exact
            values are different, hence they cannot be added together.
            */
        System.out.println("The exact scales of all three terms are different:");
        System.out.println("+ Exact scale in PI*x^3: {0:0.0000000000}" + x3Encrypted.getScale());
        System.out.println(" + Exact scale in  0.4*x: {0:0.0000000000}" + x1Encrypted.getScale());
        System.out.println(" + Exact scale in      1: {0:0.0000000000}" + plainCoeff0.getScale());

        /*
        There are many ways to fix this problem. Since P_2 and P_1 are really close
        to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
        same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
        scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
        This should not result in any noticeable error.

        Another option would be to encode 1 with scale 2^80/P_2, do a multiply_plain
        with 0.4*x, and finally rescale. In this case we would need to additionally
        make sure to encode 1 with appropriate encryption parameters (parms_id).

        In this example we will use the first (simplest) approach and simply change
        the scale of PI*x^3 and 0.4*x to 2^40.
        */
        System.out.println("Normalize scales to 2^40.");
        x3Encrypted.setScale(Math.pow(2.0, 40));
        x1Encrypted.setScale(Math.pow(2.0, 40));

        /*
        We still have a problem with mismatching encryption parameters. This is easy
        to fix by using traditional modulus switching (no rescaling). CKKS supports
        modulus switching just like the BFV scheme, allowing us to switch away parts
        of the coefficient modulus when it is simply not needed.
        */
        System.out.println("Normalize encryption parameters to the lowest level.");
        ParamsId lastParmsId = x3Encrypted.getParamsId();
        evaluator.mod_switch_to_inplace(x1Encrypted, lastParmsId);
        evaluator.mod_switch_to_inplace(plainCoeff0, lastParmsId);

        /*
        All three ciphertexts are now compatible and can be added.
        */
        System.out.println("Compute PI*x^3 + 0.4*x + 1.");
        Ciphertext encrypted_result = new Ciphertext();
        evaluator.add(x3Encrypted, x1Encrypted, encrypted_result);
        evaluator.add_plain_inplace(encrypted_result, plainCoeff0);

        /*
        First print the true result.
        */
        Plaintext plain_result = new Plaintext();
        System.out.println("Decrypt and decode PI*x^3 + 0.4x + 1.");
        System.out.println(" + Expected result: ");
        List<Double> true_result = new ArrayList<Double>();
        for (int i = 0; i < input.size(); i++) {
            double x = input.get(i);
            true_result.add((3.14159265 * x * x + 0.4)* x + 1);
        }

        /*
        Decrypt, decode, and print the result.
        */
        decryptor.decrypt(encrypted_result, plain_result);
        List<Double> result = new ArrayList<Double>();
        encoder.decode(plain_result, result);
        System.out.println("+ Computed result ...... Correct.");
        for (int i = 0; i < input.size(); i++) {
            double diff = result.get(i) - true_result.get(i);
            System.out.println("##comp res:"+i+":"+true_result.get(i)+":"+result.get(i)+":"+diff);
        }

        //////////////// TEST //////////////////////
        //System.out.println("##begin decode");
        //List<Double> dest = new ArrayList<Double>();
        ////encoder.decode(xPlain, dest);
        ////for (int i = 0; i < dest.size(); i++) {
        ////    System.out.println("##decode tag " + i + ":" + input.get(i) + ":" + dest.get(i));
        ////}
        ////List<Double> dest1 = new ArrayList<Double>();
        ////encoder.decode(plainCoeff1, dest1);
        //
        //Plaintext testplain1 = new Plaintext();
        //decryptor.decrypt(x3Encrypted, testplain1);
        //dest.clear();
        //encoder.decode(testplain1, dest);
        //for (int i = 0; i < dest.size(); i++) {
        //    System.out.println("##decode tag2 " + i + ":" + input.get(i) + ":" + dest.get(i));
        //}




    }
}
