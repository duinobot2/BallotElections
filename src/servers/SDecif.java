package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.PacketShareSK;
import utility.Schnorr;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.Utils;

/**
 * @author H¿ddεnBreakpoint
 */
public class SDecif {

    /**
     * @brief Il Server Decifratore si occupa di calcolare il Ciphertext finale, di completare la decifratura
     * e di annunciare il risultato finale
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        
        // Setting di KeyStore e TrustStore 
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreDecifer.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "decifer");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreDecifer.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "decifer");
        
        // Inizializzazione SDecif in modalitò server
        TLSServerBidi conn = new TLSServerBidi(6000);

        SSLSocket socket = conn.acceptAndCheckClient("CN=sdealer,OU=CEN,L=Campania");
        
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        // Verifica della firma sulla share della SK
        PacketShareSK packet = (PacketShareSK) in.readObject();
        if(!Schnorr.verify(packet.getSign(), packet.getSignPK(), Utils.toString(Utils.objToByteArray(packet.getSK())))){
            System.out.println("Errore controllo firma");
            
            out.writeBoolean(false);
            out.flush();
            
            out.close();
            in.close();
            socket.close();
            
            return;
        }
        
        out.writeBoolean(true);
        
        // Inizializzazione della decifratura finale
        ElGamalDec finalDec = new ElGamalDec((ElGamalSK)packet.getSK());
        
        // Invio della PK parziale
        out.writeObject(finalDec.getPK());

        out.close();
        in.close();
        socket.close();
        
        // Connessione al Dealer e lettura della PK aggregata
        socket = conn.acceptAndCheckClient("CN=sdealer,OU=CEN,L=Campania");
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        
        ElGamalPK PK=(ElGamalPK) in.readObject();
        out.writeInt(1);
        
        out.close();
        in.close();
        socket.close();
        
        // Attesa fine sessione di voto
        Thread.sleep(30000);
        
        int[] urnaPorts = {4000,4001,4002};
        
        // Invio segnale di fine sessione di voto alle urne 
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
        
        // Lettura Conteggi Locali delle urne
        for(int i=0;i<urnaPorts.length;i++){
            TLSClientBidi SUrna = new TLSClientBidi("localhost", urnaPorts[i]);
            
            ObjectOutputStream out1 = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
            ObjectInputStream in1 = new ObjectInputStream(SUrna.getcSock().getInputStream());
                       
            partialCTs[i]=(ElGamalCT)in1.readObject();
            
            out1.close();
            in1.close();
            SUrna.getcSock().close();
        }
        
        // Realizzazione Ciphertext finale
        ElGamalCT finalCT = null;
        for(int i =0;i<partialCTs.length;i++){
            if(i==0)
                finalCT=partialCTs[i];
            else
                finalCT=ElGamalCT.Homomorphism(PK, finalCT, partialCTs[i]);
        }
        
        // Invio Ciphertext finale alle urne e ricezione delle decifrature parziali
        for(int i=0;i<urnaPorts.length;i++){
            TLSClientBidi SUrna = new TLSClientBidi("localhost", urnaPorts[i]);
            
            out = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
            in = new ObjectInputStream(SUrna.getcSock().getInputStream());
            
            out.writeUTF("readyCT");
            out.writeObject(finalCT);
            finalCT=(ElGamalCT)in.readObject();
            
            out.close();
            in.close();
            SUrna.getcSock().close();
        }
        
        // Decifratura finale e annuncio risultato finale
        BigInteger RESULT=finalDec.decryptInTheExponent(finalCT);
        System.out.println("Il risultato della votazione è: "+RESULT);
        
        // Invio segnale di fine sessione alla bacheca per la pubblicazione
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
