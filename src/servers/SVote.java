/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.net.ssl.SSLSocket;
import utility.ElGamalEnc;
import utility.ElGamalPK;
import utility.TLSServerBidi;

/**
 *
 * @author duino
 */
public class SVote {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreServer.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
        TLSServerBidi SDialer = new TLSServerBidi(5000);
        
        SSLSocket socket = SDialer.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
        
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        ElGamalEnc vote = new ElGamalEnc((ElGamalPK)in.readObject());
        
        out.writeInt(1);
        
        out.close();
        in.close();
        socket.close();
        System.out.println("Sono Pronto");
    }
    
}
