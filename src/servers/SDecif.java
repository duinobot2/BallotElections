/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalGen;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.Utils;

/**
 *
 * @author duino
 */
public class SDecif {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
        
        TLSServerBidi conn = new TLSServerBidi(6000);

        SSLSocket socket = conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
        
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

        ElGamalDec finalDec = new ElGamalDec((ElGamalSK)Utils.byteArrayToObj(SKbytes));

        out.writeObject(finalDec.getPK());

        out.close();
        in.close();
        socket.close();
        
        socket = conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        
        ElGamalPK PK=(ElGamalPK) in.readObject();
        out.writeInt(1);
        
        out.close();
        in.close();
        socket.close();
        
        Thread.sleep(30000);
        
        int[] urnaPorts= {4000,4001,4002};
        int[] workerPorts= {4000,4001};
        
        for(int i=0;i<urnaPorts.length;i++){
            TLSClientBidi SUrna = new TLSClientBidi("localhost", urnaPorts[i]);
            
            out = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
            in = new ObjectInputStream(SUrna.getcSock().getInputStream());
            out.writeUTF("server");
            out.writeUTF("stop");
            
            out.close();
            in.close();
            SUrna.getcSock().close();
        }
        
        ElGamalCT[] partialCTs= new ElGamalCT[urnaPorts.length];
        
        
        for(int i=0;i<urnaPorts.length;i++){
            TLSClientBidi SUrna = new TLSClientBidi("localhost", urnaPorts[i]);
            
            ObjectOutputStream out1 = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
            ObjectInputStream in1 = new ObjectInputStream(SUrna.getcSock().getInputStream());
                       
            partialCTs[i]=(ElGamalCT)in1.readObject();
            
            out1.close();
            in1.close();
            SUrna.getcSock().close();
        }
        
        ElGamalCT finalCT = null;
        for(int i =0;i<partialCTs.length;i++){
            if(i==0)
                finalCT=partialCTs[i];
            else
                finalCT=ElGamalCT.Homomorphism(PK, finalCT, partialCTs[i]);
        }
        
        for(int i=0;i<workerPorts.length;i++){
            TLSClientBidi SUrna = new TLSClientBidi("localhost", workerPorts[i]);
            
            out = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
            in = new ObjectInputStream(SUrna.getcSock().getInputStream());
            
            out.writeUTF("readyCT");
            out.writeObject(finalCT);
            finalCT=(ElGamalCT)in.readObject();
            
            out.close();
            in.close();
            SUrna.getcSock().close();
        }
        
        BigInteger RESULT=finalDec.decryptInTheExponent(finalCT);
        System.out.println("Il risultato della votazione è: "+RESULT);
        
        TLSClientBidi SBacheca = new TLSClientBidi("localhost", 7001);
            
        out = new ObjectOutputStream(SBacheca.getcSock().getOutputStream());
        in = new ObjectInputStream(SBacheca.getcSock().getInputStream());

        out.writeUTF("stop");
        out.flush();

        out.close();
        in.close();
        SBacheca.getcSock().close();
    }
    
}
