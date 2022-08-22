/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utility;

import java.io.IOException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;

/**
 *
 * @author duino
 */
public class TLSServerBidi {
    
    private SSLServerSocket sSock;

    public TLSServerBidi(int port) throws IOException {
        SSLServerSocketFactory fact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        sSock = (SSLServerSocket) fact.createServerSocket(port);
        sSock.setNeedClientAuth(true);
    }
    
    public boolean verifyIdentity(SSLSession session, String certInfo) throws SSLPeerUnverifiedException {
        X500Principal id = (X500Principal) session.getPeerPrincipal(); // getPeerPrincipal returns info about the X500Principal of the other peer
        // X500Principal is the field that contains country, Common Name, etc.
        System.out.println("principal: " + id.getName()); // print this info
        return id.getName().equals(certInfo); 
    }
    
    public SSLSocket acceptAndCheckClient(String certInfo) throws IOException{
        SSLSocket sslSock = (SSLSocket) sSock.accept();
        sslSock.startHandshake(); // after handshake this server wants to obtain info about the connected client and 1) will print this info and 2) will execute the protocol
        
        // only with clients having a specific X500Principal 
        if (verifyIdentity(sslSock.getSession(), certInfo)) // the method getSession returns an object SSLSession that contains info about the SSL Session
        {
            return sslSock;
        } 
        
        return null;
    }
    
    public SSLSocket accept() throws IOException{
        SSLSocket sslSock = (SSLSocket) sSock.accept();
        sslSock.startHandshake(); // after handshake this server wants to obtain info about the connected client and 1) will print this info and 2) will execute the protocol
        
        return sslSock;
        
    }

    
}
