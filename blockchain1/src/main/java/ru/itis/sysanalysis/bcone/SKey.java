package ru.itis.sysanalysis.bcone;

import org.bouncycastle.util.encoders.Hex;
import java.io.File;
import java.io.FileWriter;
import java.io.Writer;
import java.security.*;

public class SKey {

    public static void main(String[] args) {

        // блок кода который генерирует нам пару public/private ключей

        KeyPairGenerator rsa;
        try (Writer publicKeyWriter = new FileWriter("public.key");
             Writer privateKeyWriter = new FileWriter("private.key")) {

            rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(1024,new SecureRandom());
            KeyPair keyPair = rsa.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            privateKeyWriter.write(new String(Hex.encode(privateKey.getEncoded())));
            publicKeyWriter.write(new String(Hex.encode(publicKey.getEncoded())));

       } catch (Exception e) {
            e.printStackTrace();
       }
    }
}
