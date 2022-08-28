package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.PacketShareSK;
import utility.PacketVote;
import utility.Schnorr;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.Utils;

/**
 * @author H¿ddεnBreakpoint
 */
public class SUrna {
    
    private TLSServerBidi conn;
    private ElGamalPK PK;
    private ElGamalDec partialDec=null;
    ArrayList<PacketVote> packetVotes; // store di packetVotes

    /**
     * @brief Inizializzazione dell'Urna (server) acquisendo la partial SK e la partial PK
     * @param numPort numero porta dell'urna corrente
     * @throws IOException
     * @throws ClassNotFoundException 
     */
    public SUrna(int numPort) throws IOException, ClassNotFoundException {
        // Creazione Server
        conn = new TLSServerBidi(numPort);
        packetVotes = new ArrayList<>();
        
        // Accettazione connessione Dealer
        SSLSocket socket = conn.acceptAndCheckClient("CN=sdealer,OU=CEN,L=Campania");

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        // Acquisizione Share e Verifica Firma
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
        
        // Inizializzazione del decifratore parziale
        partialDec = new ElGamalDec((ElGamalSK)packet.getSK());

        // Invio delle PK parziali al server Dealer
        out.writeObject(partialDec.getPK());

        out.close();
        in.close();
        socket.close();
        
        // Ricezione della PK aggregata
        socket = conn.acceptAndCheckClient("CN=sdealer,OU=CEN,L=Campania");
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        
        PK=(ElGamalPK) in.readObject();
        out.writeInt(1);
        
        out.close();
        in.close();
        socket.close();
    }
    

    /**
     * 
     * @brief I Server Urna si occupano di ricevere i voti cifrati degli elettori
     * e di partecipare alla decifratura con Threshold El Gamal Decryption
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InterruptedException 
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        System.out.println("Sono SUrna");
        
        // Setting di KeyStore e TrustStore 
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreUrna.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "servurna");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreUrna.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "servurna");
        
        // Lettura Porta del Server Urna
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter port number: ");
        int numPort = scan.nextInt();
        
        // Inizializzazione Urna
        SUrna urna = new SUrna(numPort);
        
        System.out.println("Sono pronto");
        
        // Accettazione Voti da SVote e attesa fine sessione di voto tramite segnale di SDecif
        while(true){
            SSLSocket socket = urna.conn.accept();
            
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check=in.readUTF();
            if(check.equals("server")){     //Connessione con SDecif
                
                if(urna.conn.verifyIdentity(socket.getSession(), "CN=sdecif,OU=CEN,L=Campania")){
                                
                    if(in.readUTF().equals("stop")){
                        out.close();
                        in.close();
                        socket.close();
                        break;
                    }else{
                        out.close();
                        in.close();
                        socket.close();
                        System.out.println("Error Decif command");
                    }
                }else{
                    out.close();
                    in.close();
                    socket.close();
                    System.out.println("Error SDecif identity");
                }
            
            }else if(check.equals("client")){    //Connessione con SVote
                
                if(urna.conn.verifyIdentity(socket.getSession(), "CN=svote,OU=CEN,L=Campania")){
                    PacketVote p = (PacketVote) in.readObject();
                    if(Schnorr.verify(p.getSign(), p.getSignPK(), Utils.toString(Utils.objToByteArray(p.getCT())))){
                        urna.packetVotes.add(p);
                        out.writeBoolean(true);
                    }else
                        out.writeBoolean(false);

                    System.out.println("Voto arrivato");
                }else
                    System.out.println("Error SVote identity");
                
                out.close();
                in.close();
                socket.close();
            }else{
                System.out.println("Client malevolo");
            }
            
        }
        
        // Connessione con server Bacheca per l'invio firme
        TLSClientBidi SBacheca = new TLSClientBidi("localhost", 7001);
            
        ObjectOutputStream out = new ObjectOutputStream(SBacheca.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SBacheca.getcSock().getInputStream());
        ElGamalCT finalCT = null;
        
        out.writeUTF("surnaadd");
        out.flush();
        out.writeInt(urna.packetVotes.size());
        out.flush();
        
        // Conteggio Locale e Invio delle Firme alla Bacheca
        for(int i =0;i<urna.packetVotes.size();i++){
            if(i==0)
                finalCT=urna.packetVotes.get(i).getCT();
            else
                finalCT=ElGamalCT.Homomorphism(urna.PK, finalCT, urna.packetVotes.get(i).getCT());
            
            out.writeObject(urna.packetVotes.get(i).getSign());
            out.flush();
        }


        out.close();
        in.close();
        SBacheca.getcSock().close();
        
        // Invio del Conteggio Locale a SDecif
        System.out.println("Pronto ad inviare il CT");
        SSLSocket socket = urna.conn.acceptAndCheckClient("CN=sdecif,OU=CEN,L=Campania");
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        
        out.writeObject(finalCT);
        System.out.println("inviatoCT");
        
        out.close();
        in.close();
        socket.close();

        
        // Ricezione del Ciphertext Finale e invio al Decif della decifratura parziale
        socket = urna.conn.acceptAndCheckClient("CN=sdecif,OU=CEN,L=Campania");
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        if(in.readUTF().equals("readyCT")){
            finalCT=(ElGamalCT) in.readObject();
            out.writeObject(urna.partialDec.partialDecrypt(finalCT));
            System.out.println("Work finished");
        }else{
            System.out.println("Error receive CT");
            return;
        }


        out.close();
        in.close();
        socket.close();
        
        
        
        
    }
    
}
