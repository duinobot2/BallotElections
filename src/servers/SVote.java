package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.util.encoders.Hex;
import utility.ElGamalPK;
import utility.PacketVote;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.UserPass;
import utility.Utils;

/**
 * @author H¿ddεnBreakpoint
 */
public class SVote {
    
    private static int countUrna=0;
    
    /**
     * @brief Invio del pacchetto (voto cifrato, firma, PKfirma) a una delle urne
     * @param packet pacchetto da inviare
     * @param ports porte delle urne in ascolto
     * @return res = true se l'invio è andato a buon fine, altrimenti false 
     * @throws IOException 
     */
    public static boolean sendPacketToUrna(PacketVote packet, int [] ports) throws IOException{
                
        // Connessione all'urna (Invio bilanciato)
        TLSClientBidi SUrna = new TLSClientBidi("localhost", ports[countUrna]);
        ObjectOutputStream out = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SUrna.getcSock().getInputStream());

        out.writeUTF("client");
        out.writeObject(packet);
        
        countUrna=(countUrna+1) % ports.length;
        
        // Ricezione Responso da parte dell'urna
        boolean res=in.readBoolean();

        
        out.close();
        in.close();
        SUrna.getcSock().close();
        
        return res;
        
    }
    
    /**
     * @brief Controllo Credenziali e Verifica CF per il login (se è presente nel database)
     * @param userPass oggetto contenente ID e password
     * @param session oggetto sessione TLS per recuperare il CF
     * @return response = true se i controlli sono andati a buon fine, altrimenti false 
     * @throws IOException
     * @throws ClassNotFoundException 
     */
    public static boolean checkUserPassCF(UserPass userPass, SSLSession session) throws IOException, ClassNotFoundException{
        // getPeerPrincipal returns info about the X500Principal of the other peer
        X500Principal id = (X500Principal) session.getPeerPrincipal(); 
        // X500Principal is the field that contains country, Common Name, etc.
        System.out.println("principal: " + id.getName()); // print this info
        
        String[] strings = id.getName().split(",");
        String CF=null;
        
        // Recupero CF
        for(String s : strings){
            if(s.startsWith("1.3.18.0.2.6.73")){
                CF=new String(Hex.decode(s.substring(21)));
                break;
            }
        }
        
        // Connessione al Server Reg per effettuare i controlli
        TLSClientBidi SReg = new TLSClientBidi("localhost", 7000);

        ObjectOutputStream out = new ObjectOutputStream(SReg.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SReg.getcSock().getInputStream());

        out.writeUTF("svoteCheck");
        System.out.println("svoteCheck send");
        out.flush();
        out.writeObject(userPass);
        out.flush();
        out.writeUTF(CF);
        out.flush();
        
        // Ricezione Responso da parte del server reg
        boolean response=in.readBoolean();
        
        out.close();
        in.close();
        SReg.getcSock().close();
        
        return response;
    }
    
    /**
     * @brief Inserimento firma nel database nella riga corrispondente a userPass dato in input
     * @param userPass oggetto contenente ID e password
     * @param sign firma da inserire nel database
     * @return response = true se l'inserimento a buon fine, altrimenti false 
     * @throws IOException
     * @throws ClassNotFoundException 
     */
    public static boolean setSignature(UserPass userPass, SchnorrSig sign) throws IOException, ClassNotFoundException{
        // Connessione a Server Reg
        TLSClientBidi SReg = new TLSClientBidi("localhost", 7000);

        ObjectOutputStream out = new ObjectOutputStream(SReg.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SReg.getcSock().getInputStream());
        
        // Invio ID, password e firma al Server Reg
        out.writeUTF("svoteSet");
        System.out.println("svoteSet send");
        out.flush();
        
        out.writeObject(userPass);
        out.flush();
        
        out.writeObject(sign);
        out.flush();
        
        // Ricezione Responso da parte del server reg
        boolean response=in.readBoolean();
        
        out.close();
        in.close();
        SReg.getcSock().close();
        
        return response;
    }
    
    /**
     * @brief Il Server Vote permette a ogni elettore di loggarsi e inoltra il voto alle urne
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InterruptedException 
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        System.out.println("Sono SVote");
        
        // Setting di KeyStore e TrustStore 
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreVote.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "servvote");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreVote.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "servvote");
        
        // Inizializzazione di SVote in modalità server
        TLSServerBidi conn = new TLSServerBidi(5000);
        
        SSLSocket socket = conn.acceptAndCheckClient("CN=sdealer,OU=CEN,L=Campania");
        
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        // Ricezione PK inviata dal Server Dealer
        ElGamalPK PK = (ElGamalPK)in.readObject();
        
        out.writeInt(1);
        out.flush();
        
        out.close();
        in.close();
        socket.close();

        System.out.println("Sono Pronto");
        
        // Setting porte urne a cui collegarsi
        int[] ports= {4000, 4001, 4002};
        
        //accettazione votante e invio voto a urna
        while(true){
            socket = conn.accept();
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            UserPass toCheck=(UserPass) in.readObject();
            System.out.println("tryTOCheckUserPass");
            
            // Controllo ID e password da parte del server reg
            boolean response = checkUserPassCF(toCheck, socket.getSession());
            
            out.writeBoolean(response);
            
            if(response){
           
                out.writeObject(PK);

                PacketVote p = (PacketVote) in.readObject();
                
                // Verifica della firma
                if(Schnorr.verify(p.getSign(), p.getSignPK(), Utils.toString(Utils.objToByteArray(p.getCT())))){
                                    
                    // Inserimento firma nel database del Server Reg
                    if(!setSignature(toCheck, p.getSign())){
                        out.writeBoolean(false);
                        System.out.println("Firma già presente");
                    }else // Invio del pacchetto all'urna
                        out.writeBoolean(sendPacketToUrna(p, ports));

                    System.out.println("pacchetto inviato all'urna");
                }else{
                    out.writeBoolean(false);
                    System.out.println("Firma errata");
                }
                    
            }else
                System.out.println("Invalid UserPass");
            
            out.close();
            in.close();
            socket.close();
        }
        
        
    
    }
    
}
