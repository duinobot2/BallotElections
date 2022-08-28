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
 * @author H¿ddεnBreakpoint
 */
public class SDealer {

    /**
     * @brief Il Server Dealer si occupa di generare le share di SK che serviranno per decifrare
     * con Threshold El Gamal Decryption e la PK inerente per permettere, a ogni
     * elettore, di votare.
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException{
        System.out.println("Sono SDealer");
        
        // Setting di KeyStore e TrustStore 
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreDealer.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "dealer");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreDealer.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "dealer");
        
        // Generazione (PK, SK)
        ElGamalGen generator = new ElGamalGen(512);
        
        /*
        Inizializzazione Porte di Connessione:
            4000, 4001, 4002: SUrne
            6000: SDecif
        */
        int[] secretPorts= {4000,4001,4002,6000}; 
        ElGamalPK[] PKs= new ElGamalPK[secretPorts.length];
        Schnorr signer = new Schnorr(256);
        
        // Generazione & Invio delle Share
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
        
        // Generazione PK generale partendo dalle parziali
        ElGamalPK PK = generator.aggregatePartialPublicKeys(PKs);
        
        /*
        Invio della PK a:
            4000, 4001, 4002: SUrne [omomorfismo]
            5000: SVote 
            6000: SDecif [omomorfismo]
        */
        int[] publicPorts= {4000,4001,4002,5000,6000};
        
        // Invio della PK
        for(int i=0;i<publicPorts.length;i++){
            TLSClientBidi server = new TLSClientBidi("localhost", publicPorts[i]);
            ObjectOutputStream out = new ObjectOutputStream(server.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(server.getcSock().getInputStream());
            out.writeObject(PK);
            int x = in.readInt();
            if(x==1)
                System.out.println("Send Keys Finished");
            else
                System.out.println("ERROR Send Keys Finished");

            out.close();
            in.close();
            server.getcSock().close();
        }
    }
    
}
