package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import utility.ElGamalCT;
import utility.ElGamalEnc;
import utility.ElGamalPK;
import utility.PacketVote;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.TLSClientBidi;
import utility.UserPass;
import utility.Utils;

/**
 * @author H¿ddεnBreakpoint
 */
public class Voters {

    /**
     * @brief Preparazione del pacchetto elettore, contenente voto cifrato, firma, PK firma
     * @param vote voto (1, -1, 0)
     * @param enc oggetto per cifrare il voto dell'elettore
     * @param signer oggetto per ottenere la firma dell'elettore
     * @return pacchetto elettore
     * @throws IOException 
     */   
    public static PacketVote prepareVotePacket(int vote, ElGamalEnc enc, Schnorr signer) throws IOException{
        if(vote!=0 && vote!=1 && vote!=-1) return null;
        
        ElGamalCT CT = enc.encryptInTheExponent(BigInteger.valueOf(vote));
        
        SchnorrSig sign=signer.sign(Utils.toString(Utils.objToByteArray(CT)));
        
        return new PacketVote(CT, sign, signer.getPK());
    }
    
    /**
     * @brief Registrazione Elettore e recupero credenziali
     * @param numVoter elettore i-esimo
     * @return credenziali se i controlli vanno a buon fine, altrimenti null
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws Exception 
     */
    private static UserPass getUserPass(int numVoter) throws IOException, ClassNotFoundException, Exception {
        
        // Connessione al server Register con il certificato dell'elettore i-esimo
        TLSClientBidi SReg = new TLSClientBidi("localhost", 7000, ".\\cert\\voter"+ numVoter +".jks", "voter" + numVoter);
        
        ObjectOutputStream out = new ObjectOutputStream(SReg.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SReg.getcSock().getInputStream());

        out.writeUTF("voter");
        out.flush();

        int dim = in.readInt();
        if(dim==-1)
            return null;
        
        // Recupero credenziali a registrazione avvenuta
        UserPass userPass = (UserPass) in.readObject();

        out.close();
        in.close();
        SReg.getcSock().close();
        
        return userPass;
    }
    
    /**
     * @brief Scelta del candidato e invio pacchetto
     * @param userPass credenziali elettore
     * @param vote preferenza elettore
     * @param numVoter elettore i-esimo
     * @return response = true se la votazione è andata a buon fine, altrimenti false
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws Exception 
     */
    private static boolean vote(UserPass userPass, int vote, int numVoter) throws IOException, ClassNotFoundException, Exception{
        
        // Connessione al Server Vote con il certificato dell'elettore i-esimo per il login
        TLSClientBidi SVote = new TLSClientBidi("localhost", 5000, ".\\cert\\voter"+ numVoter +".jks", "voter" + numVoter);
        
        ObjectOutputStream out = new ObjectOutputStream(SVote.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SVote.getcSock().getInputStream());
        
        out.writeObject(userPass);
        out.flush();

        // Controllo credenziali
        if(!in.readBoolean()){
            System.out.println("Errore userPass errate");
            return false;
        }
        
        // Inizializzazione oggetti per cifrare e firmare
        ElGamalEnc enc = new ElGamalEnc((ElGamalPK) in.readObject());
        Schnorr signer = new Schnorr(256);
        
        // Creazione del pacchetto elettore e Invio
        PacketVote p = prepareVotePacket(vote, enc, signer);
        out.writeObject(p);
        
        // Controllo Responso SVote
        boolean response=in.readBoolean();
        
        out.close();
        in.close();
        SVote.getcSock().close();
        
        return response;
        
    }

    /**
     * @brief L'elettore si registra alla piattaforma di voto elettronico remoto ed esprime la propria preferenza
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws Exception 
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, Exception {
        System.out.println("Sono Voters");
        
        // Setting TrustStore
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreVoters.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "voters");
        
        System.out.println("Responso votanti:");
        
        // Elettore 1 che si logga con password errata
        UserPass error = getUserPass(1);
        String realPass=error.getPassword();
        error.setPassword("resfsddf");
        System.out.println(vote(error, 1, 1));
        
        // Elettore 1 che si logga con la password corretta
        error.setPassword(realPass);
        System.out.println(vote(error, 1, 1));
        
        // Elettore 1 che si logga 2 volte
        error.setPassword(realPass);
        System.out.println(vote(error, -1, 1));
        
        // Ladro (elettore 3) non registrato che prova a loggarsi con le credenziali dell'elettore 2
        error=getUserPass(2);
        System.out.println(vote(error, 0, 3));
        
        // Elettori onesti
        System.out.println(vote(error, 0, 2));
        System.out.println(vote(getUserPass(3), 1, 3));
        System.out.println(vote(getUserPass(4), -1, 4));
        System.out.println(vote(getUserPass(5), 0, 5));
        System.out.println(vote(getUserPass(6), 1, 6));
        
        // Elettore 6 che prova a registrarsi più di una volta
        System.out.println(getUserPass(6)!=null);
        
        // Elettore 7 (barese) non residente nella zona di ballottaggio (Campania)
        System.out.println(getUserPass(7)!=null);
        
    }

}
