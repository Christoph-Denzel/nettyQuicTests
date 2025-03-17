package denzel.clientAuthentication;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Util {

    public static X509TrustManager getTrustManager() {
        try {
            var certStream = new FileInputStream("src/main/resources/certificate0.der");
            var privateKeyStream = new FileInputStream("src/main/resources/privateKey0.txt");

            var certificate = CertificateFactory.getInstance("X.509").generateCertificate(certStream);
            byte[] keyBytes = Base64.getMimeDecoder().decode(privateKeyStream.readAllBytes());
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            var privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);

            var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("Cert", certificate);
            keyStore.setKeyEntry("key", privateKey, "".toCharArray(), new Certificate[]{certificate});
            var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            var kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, "".toCharArray());

            var trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            certStream.close();
            privateKeyStream.close();
            return trustManager;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyManager getKeyManager() {
        try {
            var certStream = new FileInputStream("src/main/resources/certificate0.der");
            var privateKeyStream = new FileInputStream("src/main/resources/privateKey0.txt");

            var certificate = CertificateFactory.getInstance("X.509").generateCertificate(certStream);
            byte[] keyBytes = Base64.getMimeDecoder().decode(privateKeyStream.readAllBytes());
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            var privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);

            var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("Cert", certificate);
            keyStore.setKeyEntry("key", privateKey, "".toCharArray(), new Certificate[]{certificate});

            var kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, "".toCharArray());

            var keyManager = (X509KeyManager) kmf.getKeyManagers()[0];
            certStream.close();
            privateKeyStream.close();
            return keyManager;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
