/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utility;

import java.io.IOException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 *
 * @author duino
 */
public class TLSClientBidi {
    
    private SSLSocket cSock;

    public TLSClientBidi(String hostAddr, int port) throws IOException {
        SSLSocketFactory sockfact = (SSLSocketFactory)SSLSocketFactory.getDefault(); // similar to the server except 
        cSock = (SSLSocket)sockfact.createSocket(hostAddr, port); // specify host and port
        cSock.startHandshake(); // this is optional - if you do not request explicitly handshake the handshake
    }
    
    public SSLSocket getcSock() {
        return cSock;
    }
    
    

}
