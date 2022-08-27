/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 *
 * @author duino
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

    public TLSClientBidi(String hostAddr, int port) throws IOException {
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault(); // similar to the server except 
        cSock = (SSLSocket) sockfact.createSocket(hostAddr, port); // specify host and port
        cSock.startHandshake(); // this is optional - if you do not request explicitly handshake the handshake
    }
    
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
