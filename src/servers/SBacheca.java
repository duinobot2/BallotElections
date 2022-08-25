/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import javax.net.ssl.SSLSocket;
import utility.SchnorrSig;
import utility.TLSServerBidi;

/**
 *
 * @author duino
 */
public class SBacheca {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
        ArrayList<SchnorrSig> signatureList = new ArrayList<>();
        TLSServerBidi conn = new TLSServerBidi(7001);
        
        while (true) {
            SSLSocket socket = conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check = in.readUTF();
            System.out.println(check);
            
            if (check.equals("surnaadd")) {
                int numSign=in.readInt();
                for(int i=0;i<numSign;i++)
                    signatureList.add((SchnorrSig) in.readObject());
                out.close();
                in.close();
                socket.close();
            }else if(check.equals("stop")){
                out.close();
                in.close();
                socket.close();
                break;
            }
            
        }
        
        System.out.println("Stampa bacheca:");
        for(SchnorrSig sig : signatureList){
            System.out.println(sig);
        }
    }
    
}
