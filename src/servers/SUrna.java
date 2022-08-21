/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalEnc;
import utility.ElGamalGen;
import utility.ElGamalSK;
import utility.TLSServerBidi;
import utility.Utils;

/**
 *
 * @author duino
 */
public class SUrna {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreServer.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter port number: ");

        // This method reads the number provided using keyboard
        int numPort = scan.nextInt();

        // Closing Scanner after the use
        scan.close();
        
        TLSServerBidi SDialer = new TLSServerBidi(numPort);
        
        SSLSocket socket = SDialer.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
        
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        ElGamalGen tempGen = new ElGamalGen(64);
        ElGamalDec tempDec = new ElGamalDec(tempGen.getSK());
        
        out.writeObject(tempGen.getPK());
        
        int dim = in.readInt();
        
        byte[] SKbytes = new byte[dim];

        for(int i =0;i<dim;i++){
            SKbytes[i]=tempDec.decrypt((ElGamalCT)in.readObject()).byteValue();
        }
        
        ElGamalDec urna = new ElGamalDec((ElGamalSK)Utils.byteArrayToObj(SKbytes));

        out.writeObject(urna.getPK());
        
        out.close();
        in.close();
        socket.close();
        
        System.out.println("Sono pronto");
        
    }
    
}
