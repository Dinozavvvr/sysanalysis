package ru.itis.sysanalysis.bcone;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Utils {

    public static final String DIGEST_ALGORITHM = "SHA-256";
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGN_ALGORITHM = "SHA256withRSA";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] getHash(BlockInfo blockInfo) throws NoSuchAlgorithmException, NoSuchProviderException {

        StringBuilder info = new StringBuilder();
        for (String s : blockInfo.getData()) {
            info.append(s);
        }

        MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM, "BC");

        return digest.digest(
                concat(blockInfo.getPrevHash(),
                        info.toString().getBytes(StandardCharsets.UTF_8))
        );
    }

    public static byte[] concat(byte[] a, byte[] b) {
        if (a == null) return b;
        if (b == null) return a;
        int len_a = a.length;
        int len_b = b.length;
        byte[] C = new byte[len_a + len_b];
        System.arraycopy(a, 0, C, 0, len_a);
        System.arraycopy(b, 0, C, len_a, len_b);
        return C;
    }

    public static KeyPair loadKeys() throws Exception {

        byte[] publicKeyHex = Files.readAllBytes(Paths.get("public.key"));
        byte[] privateKeyHex = Files.readAllBytes(Paths.get("private.key"));

        PublicKey publicKey = convertArrayToPublicKey(Hex.decode(publicKeyHex), KEY_ALGORITHM);
        PrivateKey privateKey = convertArrayToPrivateKey(Hex.decode(privateKeyHex), KEY_ALGORITHM);

        return new KeyPair(publicKey, privateKey);
    }


    public static PublicKey convertArrayToPublicKey(byte[] encoded, String algorithm) throws Exception {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

        return keyFactory.generatePublic(pubKeySpec);
    }

    public static PrivateKey convertArrayToPrivateKey(byte[] encoded, String algorithm) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

        return keyFactory.generatePrivate(keySpec);
    }

    public static byte[] generateRSAPSSSignature(PrivateKey privateKey, byte[] input)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGN_ALGORITHM, "BC");

        signature.initSign(privateKey);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifyRSAPSSSignature(PublicKey publicKey, byte[] input, byte[] encSignature)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGN_ALGORITHM, "BC");

        signature.initVerify(publicKey);

        signature.update(input);

        return signature.verify(encSignature);
    }
}
