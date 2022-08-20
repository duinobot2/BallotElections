/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ballotelections;

import java.io.IOException;
import javax.net.ssl.SSLSocket;
import utility.TLSServerBidi;

/**
 *
 * @author duino
 */
public class TLSTestServer {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException{
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\ballotelections\\keystoreServer.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\ballotelections\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        TLSServerBidi server = new TLSServerBidi(4000) {
            @Override
            public void exchangeInfoWithClient(SSLSocket sslSock) {
                return;
            }
        };
        
        server.acceptAndCheckClient("");
        
    }
    
}
