package ru.itis.sa.arbiter.ts;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
public class TSPRestController {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGN_ALGORITHM = "SHA256withRSA";
    private static final String privateKeyStr = "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100a811365d2f3642952751029edf87c8fa2aeb6e0feafcf800190a7dd2cf750c63262f6abd8ef52b251c0e10291d5e2f7e6682de1aae1d64d4f9b242050f898744ca300a44c4d8fc8af0e7a1c7fd9b606d7bde304b29bec01fbef554df6ba1b7b1ec355e1ff68bd37f3d40fb27d1aa233fe3dd6b63f7241e734739851ce8c590f7020301000102818019a116533b81e0c1720f6e80dfc18b2a6b251fd1999a1e0f95c1fdd20a04e570b14005dd0651e8d46de4cf1e15f668f3b39a3d588038c7499b124df30b9d835d007173897de36ed60b741be71d9c0c92539bc5d8d8c81c217e35768afa4f5deb208adc074646747b64bddf401d24fc27d989073b811145e3f26453e50dff9391024100e8ba466033c207db1c886a385e0933bb592bd279f436dcdd809516e6c9ff2a3bce740668c9ec306f536694e79f47aac1854e59eed67ae9b04a4387ceff2fd8cb024100b8dfa8debdbd3b732a3b108b0669985f8c064bdedf219b98ddbaf3d43c57cd13caea5d247e3099bdf6d553e9182d76fc8f002a7ee7ac27277ee0010f5cc95f0502405c90f2bb02fb330ab8cf9d882c06f6f796a1328765568904e546e7a4064622b3450bab1cf4eba7dc2fcd067f1640782f9ee92a263053152e146bc5d1d478607f024100a5cd310e52ec9b9cb58b3352fbf5480aa8f21ca94d443edfe23c00e19f1cbf77b8cc67ac8adfdb825b1507a44d62b90bd8d435488b4e01ef920223f13b2dfe61024100cf1d242fb3c7bf46f6c222756122db17326894108af890d645cc787f38798b4c0e8500625bf66b548855768583ef53c21be5f8d46d9076552fe32f75c3461e53";
    private static final String publicKeyStr = "30819f300d06092a864886f70d010101050003818d0030818902818100a811365d2f3642952751029edf87c8fa2aeb6e0feafcf800190a7dd2cf750c63262f6abd8ef52b251c0e10291d5e2f7e6682de1aae1d64d4f9b242050f898744ca300a44c4d8fc8af0e7a1c7fd9b606d7bde304b29bec01fbef554df6ba1b7b1ec355e1ff68bd37f3d40fb27d1aa233fe3dd6b63f7241e734739851ce8c590f70203010001";
    public static String publicKey64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCoETZdLzZClSdRAp7fh8j6KutuD+r8+AAZCn3Sz3UMYyYvar2O9SslHA4QKR1eL35mgt4arh1k1PmyQgUPiYdEyjAKRMTY/Irw56HH/ZtgbXveMEspvsAfvvVU32uht7HsNV4f9ovTfz1A+yfRqiM/491rY/ckHnNHOYUc6MWQ9wIDAQAB";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ResponseBody
    @RequestMapping(value = "/ts")
    public TimeStampResp getTS(@RequestParam(name = "digest", required = false)String digestStr) {
        TimeStampResp resp = null;
        try {
            PrivateKey privateKey = convertArrayToPrivateKey(Hex.decode(privateKeyStr.getBytes()),KEY_ALGORITHM);

            String date = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SX").format(new Date());
            byte[] digest = Hex.decode(digestStr.getBytes());
            byte[] input = concat(date.getBytes(), digest);
            byte[] sign = generateRSAPSSSignature(privateKey,input);

            TimeStampToken ts = new TimeStampToken(date, new String(Hex.encode(sign)));
            resp = new TimeStampResp(0, "", ts);
        } catch (Exception e) {
            resp = new TimeStampResp(2, "rejection", null);
            e.printStackTrace();
        }

        return resp;
    }

    @ResponseBody
    @RequestMapping(value = "/ts/public")
    public String getPublic() {
        return publicKeyStr;
    }

    @ResponseBody
    @RequestMapping(value = "/ts/public64")
    public String getPublic64() {
        return publicKey64;
    }

    @ResponseBody
    @RequestMapping("/ts/index")
    public void index(HttpServletResponse response) {

        try {
            OutputStream pw = (response.getOutputStream());
            byte[] indexFile = getClass().getResourceAsStream("/resources/ts.html").readAllBytes();
            pw.write(indexFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static PublicKey convertArrayToPublicKey(byte encoded[], String algorithm) throws Exception {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        return pubKey;
    }

    public static PrivateKey convertArrayToPrivateKey(byte encoded[], String algorithm) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PrivateKey priKey = keyFactory.generatePrivate(keySpec);
        return priKey;
    }

    public static byte[] generateRSAPSSSignature(PrivateKey privateKey, byte[] input)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGN_ALGORITHM, "BC");

        signature.initSign(privateKey);

        signature.update(input);

        return signature.sign();
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
