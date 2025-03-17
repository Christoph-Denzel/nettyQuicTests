package denzel.clientAuthentication;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustManagerWrapper implements X509TrustManager {

    private final X509TrustManager trustManager;

    public TrustManagerWrapper(X509TrustManager trustManager) {
        this.trustManager = trustManager;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        //return new X509Certificate[0]; //works
        return trustManager.getAcceptedIssuers(); //Does not work for client authentication
    }

}
