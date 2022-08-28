/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import utility.ElGamalGen;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.PacketShareSK;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.TLSClientBidi;
import utility.Utils;

/**
 *
 * @author duino
 */
public class SDealer {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException{
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreDealer.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "dealer");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreDealer.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "dealer");
        
        ElGamalGen generator = new ElGamalGen(512);
        
        int[] secretPorts= {4000,4001,4002,6000};
        ElGamalPK[] PKs= new ElGamalPK[secretPorts.length];
        Schnorr signer = new Schnorr(256);
        
        for(int i=0;i<secretPorts.length;i++){
            TLSClientBidi SUrna = new TLSClientBidi("localhost", secretPorts[i]);

            ObjectOutputStream out = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(SUrna.getcSock().getInputStream());
            
            ElGamalSK SKPartial = generator.getPartialSecret();
            
            SchnorrSig sign=signer.sign(Utils.toString(Utils.objToByteArray(SKPartial)));
            
            out.writeObject(new PacketShareSK(SKPartial, sign, signer.getPK()));
            
            if(in.readBoolean()==false){
                System.out.println("Errore firma digitale");
                return;
            }
             
            PKs[i] =(ElGamalPK) in.readObject();
            out.close();
            in.close();
            SUrna.getcSock().close();
        }
        
        ElGamalPK PK = generator.aggregatePartialPublicKeys(PKs);
        
        int[] publicPorts= {4000,4001,4002,5000,6000};
        
        for(int i=0;i<publicPorts.length;i++){
            TLSClientBidi SVote = new TLSClientBidi("localhost", publicPorts[i]);
            ObjectOutputStream out = new ObjectOutputStream(SVote.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(SVote.getcSock().getInputStream());
            out.writeObject(PK);
            int x = in.readInt();
            if(x==1)
                System.out.println("Send Keys Finished");
            else
                System.out.println("ERROR Send Keys Finished");

            out.close();
            in.close();
            SVote.getcSock().close();
        }
    }
    
}
