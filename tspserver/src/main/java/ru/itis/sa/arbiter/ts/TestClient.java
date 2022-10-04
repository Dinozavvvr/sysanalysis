package ru.itis.sa.arbiter.ts;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import ru.itis.sa.arbiter.neurobc.BlockModel;
import ru.itis.sa.arbiter.ts.TimeStampResp;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestClient {

    /* хеш для подписи */
    public static final String digest = "1F4A121121123123189002BC";
    /* 16-ричное представление публичного ключа сервиса */
    public static String publicKey = "30819f300d06092a864886f70d010101050003818d0030818902818100a811365d2f3642952751029edf87c8fa2aeb6e0feafcf800190a7dd2cf750c63262f6abd8ef52b251c0e10291d5e2f7e6682de1aae1d64d4f9b242050f898744ca300a44c4d8fc8af0e7a1c7fd9b606d7bde304b29bec01fbef554df6ba1b7b1ec355e1ff68bd37f3d40fb27d1aa233fe3dd6b63f7241e734739851ce8c590f70203010001";
    /* алгоритм ключа сервиса */
    public static final String KEY_ALGORITHM = "RSA";
    /* алгоритм подписи, формируемой сервисом */
    public static final String SIGN_ALGORITHM = "SHA256withRSA";


    public static void main(String[] args) {
        System.out.println(Base64.getEncoder().encodeToString(Hex.decode(publicKey))
        );
        //readPublicKey();
        //readAndVerifyTimeStamp();
    }

    /*
        Запрос публичного ключа с сервиса
     */
    public static void readPublicKey() {
        try {
            URL url = new URL("http://89.108.115.118/ts/public");

            HttpURLConnection con = (HttpURLConnection) url.openConnection();

            con.setRequestMethod("GET");

            int rcode = con.getResponseCode();

            if (rcode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));

                publicKey = reader.readLine();

                System.out.println(publicKey);
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /*
        Запрос подписи хеша с меткой времени
     */
    public static void readAndVerifyTimeStamp() {
        try {
            URL url = new URL("http://89.108.115.118/ts?digest=" + digest);

            HttpURLConnection con = (HttpURLConnection) url.openConnection();

            con.setRequestMethod("GET");

            int rcode = con.getResponseCode();

            if (rcode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));

                String response = reader.readLine();

                ObjectMapper mapper = new ObjectMapper();
                TimeStampResp timeStampResp = mapper.readValue(response, TimeStampResp.class);

                String timeStamp = timeStampResp.getTimeStampToken().getTs();
                String signHexStr = timeStampResp.getTimeStampToken().getSignature();

                /* формируем объединенный массив данных, которые были подписаны (метка времени + хеш) */
                byte[] data = new byte[timeStamp.getBytes().length + Hex.decode(digest).length];
                System.arraycopy(timeStamp.getBytes(), 0, data, 0, timeStamp.getBytes().length);
                System.arraycopy(Hex.decode(digest), 0, data, timeStamp.getBytes().length, Hex.decode(digest).length);

                /* Верификация подписи signHexStr, наложенной сервисом на данные (метка времени + хеш)  */
                System.out.println(verify(publicKey, data, signHexStr));
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean verify(String publicKeyHexStr, byte[] data, String signHexStr) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            Signature signature = Signature.getInstance(SIGN_ALGORITHM, "BC");

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Hex.decode(publicKeyHexStr));
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
            signature.initVerify(pubKey);

            signature.update(data);

            return signature.verify(Hex.decode(signHexStr));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
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

}
