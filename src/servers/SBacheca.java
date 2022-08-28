package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import javax.net.ssl.SSLSocket;
import utility.SchnorrSig;
import utility.TLSServerBidi;

/**
 * @author H¿ddεnBreakpoint
 */
public class SBacheca {

    /**
     * @brief Il Server Bacheca riceve le firme dai server urna e le pubblica solo dopo l'annuncio del risultato finale
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        
        // Setting di KeyStore e TrustStore 
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreBacheca.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "bacheca");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreBacheca.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "bacheca");
        
        ArrayList<SchnorrSig> signatureList = new ArrayList<>();
        
        // Inizializzazione bacheca in modalità server
        TLSServerBidi conn = new TLSServerBidi(7001);
        
        // Ricezione firme da parte delle urne e attesa segnale di stop
        while (true) {
            SSLSocket socket = conn.accept();

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check = in.readUTF();
            System.out.println(check);
            
            if (check.equals("surnaadd")) { // Connessione con le urne
                if(conn.verifyIdentity(socket.getSession(), "CN=surna,OU=CEN,L=Campania")){
                    int numSign=in.readInt();
                    for(int i=0;i<numSign;i++)
                        signatureList.add((SchnorrSig) in.readObject());
                }else
                    System.out.println("Error SUrna identity");
                
                out.close();
                in.close();
                socket.close();
            }else if(check.equals("stop")){ // Connessione con SDecif
                boolean idCheck=conn.verifyIdentity(socket.getSession(), "CN=sdecif,OU=CEN,L=Campania");
                out.close();
                in.close();
                socket.close();
                if(idCheck)             
                    break;
                else
                    System.out.println("Error SDecif identity");
            }
            
        }
        
        // Pubblicazione firme sulla bacheca
        System.out.println("Stampa bacheca:");
        for(SchnorrSig sig : signatureList){
            System.out.println(sig);
        }
    }
    
}
