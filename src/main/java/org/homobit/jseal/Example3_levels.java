package org.homobit.jseal;

import java.util.List;

public class Example3_levels {
    public static void main(String[] args) {
        EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
        long poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);

        parms.set_coeff_modulus(CoeffModulus.create(poly_modulus_degree, new int[]{ 50, 30, 30, 50, 50 }));

        parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20));

        SealContext context = new SealContext(parms);
        SealContext.ContextData contextData = context.getKeyContextData();
        System.out.println("---->Level chain index:" + contextData.getChainIndex());
        System.out.println("      parms_id:" + contextData.getParamsId());

        List<SmallModulus> coeffModulus = contextData.getParams().get_coeff_modulus();
        for (SmallModulus mod: coeffModulus) {
            System.out.println(Long.toHexString(mod.getValue())+" ");
        }

        /*
        Next iterate over the remaining (data) levels.
        */
        contextData = context.getFirstContextData();
        while (contextData != null) {
            System.out.println(" Level (chain index): " + contextData.getChainIndex());
            if (contextData.getParamsId().equals(context.getFirstParamsId())) {
                System.out.println(" ...... first_context_data()");
            } else if (contextData.getParamsId().equals(context.getLastParamsId())) {
                System.out.println(" ...... last_context_data()");
            } else {
                System.out.println();
            }
            System.out.println("      parms_id: " + contextData.getParamsId());
            System.out.println("      coeff_modulus primes: ");
            for(SmallModulus prime: contextData.getParams().get_coeff_modulus() ) {
                System.out.println(Long.toHexString(prime.getValue()));
            }
            System.out.println("\\");
            System.out.println(" \\-->");
            contextData = contextData.getNextContextData();
        }
        System.out.println(" End of chain reached");

        /*
        We create some keys and check that indeed they appear at the highest level.
        */
        KeyGenerator keyGenerator = new KeyGenerator(context);
        PublicKey publicKey = keyGenerator.getPublicKey();
        SecretKey secretKey = keyGenerator.getSecretKey();
        RelinKeys relinKeys = keyGenerator.getRelinKeys();
        GaloisKeys galoisKeys = keyGenerator.getGaloisKeys();
        System.out.println("Print the parameter IDs of generated elements.");
        System.out.println("   + public_key:  " + publicKey.getParamsId());
        System.out.println("   + secret_key:  " + secretKey.getParamsId());
        System.out.println("   + relin_keys:  " + relinKeys.getParamsId());
        System.out.println("   + galois_keys:  " + galoisKeys.getParamsId());

        Encryptor encryptor = new Encryptor(context, publicKey);
        Evaluator evaluator = new Evaluator(context);
        Decryptor decryptor = new Decryptor(context, secretKey);

        /*
        In the BFV scheme plaintexts do not carry a parms_id, but ciphertexts do. Note
        how the freshly encrypted ciphertext is at the highest data level.
        */
        Plaintext plaintext = new Plaintext("1x^3 + 2x^2 + 3x^1 + 4");
        Ciphertext encrypted = new Ciphertext();
        encryptor.encrypt(plaintext, encrypted);
        System.out.println("    + plain:       " + plaintext.getParamsId() + " (not set in BFV)");
        System.out.println("    + encrypted:   " + encrypted.getParamsId());

        /*
        `Modulus switching' is a technique of changing the ciphertext parameters down
        in the chain. The function Evaluator::mod_switch_to_next always switches to
        the next level down the chain, whereas Evaluator::mod_switch_to switches to
        a parameter set down the chain corresponding to a given parms_id. However, it
        is impossible to switch up in the chain.
        */
        System.out.println("Perform modulus switching on encrypted and print.");
        contextData = context.getFirstContextData();
        System.out.println("---->");
        while (contextData.getNextContextData() != null) {
            System.out.println(" Level (chain index): " + contextData.getChainIndex());
            System.out.println(" Level (chain index): " + encrypted.getParamsId());
            System.out.println("      Noise budget at this level: " + decryptor.invariant_noise_budget(encrypted) + " bits");
            System.out.println("\\");
            System.out.println(" \\-->");
            evaluator.mod_switch_to_next_inplace(encrypted);
            contextData = contextData.getNextContextData();
        }
        System.out.println(" Level (chain index): " + contextData.getChainIndex());
        System.out.println("      parms_id of encrypted: " + encrypted.getParamsId());
        System.out.println("      Noise budget at this level: " + decryptor.invariant_noise_budget(encrypted) + " bits");
        System.out.println("\\");
        System.out.println(" \\-->");
        System.out.println(" End of chain reached");

        /*
        At this point it is hard to see any benefit in doing this: we lost a huge
        amount of noise budget (i.e., computational power) at each switch and seemed
        to get nothing in return. Decryption still works.
        */
        System.out.println("Decrypt still works after modulus switching.");
        decryptor.decrypt(encrypted, plaintext);
        System.out.println("    + Decryption of encrypted: " + plaintext.toString());
        System.out.println(" ...... Correct.");

        /*
        However, there is a hidden benefit: the size of the ciphertext depends
        linearly on the number of primes in the coefficient modulus. Thus, if there
        is no need or intention to perform any further computations on a given
        ciphertext, we might as well switch it down to the smallest (last) set of
        parameters in the chain before sending it back to the secret key holder for
        decryption.

        Also the lost noise budget is actually not an issue at all, if we do things
        right, as we will see below.

        First we recreate the original ciphertext and perform some computations.
        */
        System.out.println("Computation is more efficient with modulus switching.");
        System.out.println("Compute the 8th power.");
        encryptor.encrypt(plaintext, encrypted);
        System.out.println("    + Noise budget fresh:                   " + decryptor.invariant_noise_budget(encrypted) + " bits");
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, relinKeys);
        System.out.println("    + Noise budget of the 2nd power:        " + decryptor.invariant_noise_budget(encrypted) + "bits");
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, relinKeys);
        System.out.println("    + Noise budget of the 4nd power:        " + decryptor.invariant_noise_budget(encrypted) + "bits");

        /*
        Surprisingly, in this case modulus switching has no effect at all on the
        noise budget.
        */
        evaluator.mod_switch_to_next_inplace(encrypted);
        System.out.println("    + Noise budget after modulus switching: " + decryptor.invariant_noise_budget(encrypted) + "bits");

        /*
        This means that there is no harm at all in dropping some of the coefficient
        modulus after doing enough computations. In some cases one might want to
        switch to a lower level slightly earlier, actually sacrificing some of the
        noise budget in the process, to gain computational performance from having
        smaller parameters. We see from the print-out that the next modulus switch
        should be done ideally when the noise budget is down to around 25 bits.
        */
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, relinKeys);
        System.out.println("    + Noise budget of the 8nd power:        " + decryptor.invariant_noise_budget(encrypted) + "bits");
        evaluator.mod_switch_to_next_inplace(encrypted);
        System.out.println("    + Noise budget after modulus switching: " + decryptor.invariant_noise_budget(encrypted) + "bits");

        /*
        At this point the ciphertext still decrypts correctly, has very small size,
        and the computation was as efficient as possible. Note that the decryptor
        can be used to decrypt a ciphertext at any level in the modulus switching
        chain.
        */
        decryptor.decrypt(encrypted, plaintext);
        System.out.println("    + Decryption of the 8th power (hexadecimal) ...... Correct.");
        System.out.println("    " + plaintext.toString());

        /*
        In BFV modulus switching is not necessary and in some cases the user might
        not want to create the modulus switching chain, except for the highest two
        levels. This can be done by passing a bool `false' to SEALContext::Create.
        */
        context = new SealContext(parms, false);

        /*
        We can check that indeed the modulus switching chain has been created only
        for the highest two levels (key level and highest data level). The following
        loop should execute only once.
        */
        System.out.println("Optionally disable modulus switching chain expansion.");
        System.out.println("Print the modulus switching chain.");
        System.out.println("---->");
        for (contextData = context.getKeyContextData(); contextData != null; contextData = contextData.getNextContextData()) {
            System.out.println(" Level (chain index): " + contextData.getChainIndex());
            System.out.println("      parms_id: " + contextData.getParamsId());
            System.out.println("      coeff_modulus primes: ");
            for (SmallModulus mod: contextData.getParams().get_coeff_modulus()) {
                System.out.println(Long.toHexString(mod.getValue()) + " ");
            }
            System.out.println("\\");
            System.out.println(" \\--->");
            System.out.println(" End of chain reached");
        }

    }
}
