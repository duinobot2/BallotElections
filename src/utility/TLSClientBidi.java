package utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief TLS con autenticazione bidirezionale Lato Client
 */
public class TLSClientBidi {

    private SSLSocket cSock;

    private SSLContext createSSLContext(String keystoreFile, String keystorePass) throws Exception {
        KeyManagerFactory keyFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore clientStore = KeyStore.getInstance("JKS");

        clientStore.load(new FileInputStream(keystoreFile), keystorePass.toCharArray());

        keyFact.init(clientStore, keystorePass.toCharArray());

        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");
        // there are two options: one call init with keyFact.getKeyManagers() and in this case it uses the first matching key from keystoreclient.jks 
        // or uses MyKeyManager as shown below specifying as first parameter the keystore file, second parameter the password and third the alias that points to the key
        // you want to use.
        //
        //sslContext.init(new X509KeyManager[] {new MyKeyManager("keystore.jks","changeit".toCharArray(),"ssltest") },null, null);
        sslContext.init(keyFact.getKeyManagers(), null, null);

        return sslContext;
    }

    /**
     * @brief Costruttore di Default
     * @param hostAddr indirizzo server
     * @param port porta server
     * @throws IOException 
     */
    public TLSClientBidi(String hostAddr, int port) throws IOException {
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault(); // similar to the server except 
        cSock = (SSLSocket) sockfact.createSocket(hostAddr, port); // specify host and port
        cSock.startHandshake(); // this is optional - if you do not request explicitly handshake the handshake
    }
    
    /**
     * @brief Costruttore con KeyStore dinamico
     * @param hostAddr indirizzo server
     * @param port porta server
     * @param keystoreFile Percorso del KeyStore in input
     * @param keystorePass Password del KeyStore in input
     * @throws IOException
     * @throws Exception 
     */
    public TLSClientBidi(String hostAddr, int port, String keystoreFile, String keystorePass) throws IOException, Exception {
        SSLContext sslContext = createSSLContext(keystoreFile,keystorePass); 
        SSLSocketFactory fact = sslContext.getSocketFactory(); 
        cSock = (SSLSocket)fact.createSocket(hostAddr, port);

        cSock.startHandshake(); // this is optional - if you do not request explicitly handshake the handshake
    }

    public SSLSocket getcSock() {
        return cSock;
    }

}
