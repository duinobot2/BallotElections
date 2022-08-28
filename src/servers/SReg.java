package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.util.encoders.Hex;
import utility.SchnorrSig;
import utility.TLSServerBidi;
import utility.TableUserPass;
import utility.UserPass;
import utility.Utils;

/**
 * @author H¿ddεnBreakpoint
 */
public class SReg {
    
    /**
     * @brief Controlli sull'elettore in fase di registrazione
     * @param tableCF tabella del database contenente i CF degli utenti registrati
     * @param session oggetto sessione TLS per recuperare i dati sull'elettore (CF, età, residenza, nazionalità)
     * @return true se la registrazione avviene con successo (controlli superati e CF salvato), altrimenti false
     * @throws SSLPeerUnverifiedException 
     */
    public static boolean verifyAndSaveCF(HashSet<String> tableCF, SSLSession session) throws SSLPeerUnverifiedException {
        // getPeerPrincipal returns info about the X500Principal of the other peer
        X500Principal id = (X500Principal) session.getPeerPrincipal(); 
        // X500Principal is the field that contains country, Common Name, etc.
        System.out.println("principal: " + id.getName()); // print this info
        
        String[] strings = id.getName().split(",");
        String CF = null, data = null, provincia = null, cittadinanza = null;
        
        // Recupero delle informazioni dell'elettore
        for (String s : strings) {
            if (s.startsWith("1.3.18.0.2.6.73")) {
                CF = new String(Hex.decode(s.substring(21)));
            } else if (s.startsWith("1.3.6.1.4.1.2787.100.1.1.9")) {
                data = new String(Hex.decode(s.substring(32)));
            } else if (s.startsWith("ST")) {
                provincia = s.substring(3);
            } else if (s.startsWith("C")) {
                cittadinanza = s.substring(2);
            }
        }
        
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy");
        LocalDate birthDate = LocalDate.parse(data, formatter);
        
        System.out.println(birthDate + " " + CF + " " + provincia + " " + cittadinanza);
        
        // Controlli su cittadinanza e residenza
        if (!cittadinanza.equals("IT") || (!provincia.equals("Salerno") && !provincia.equals("Napoli") && !provincia.equals("Avellino")
                && !provincia.equals("Caserta") && !provincia.equals("Benevento"))) {
            return false;
        }
        
        // Controllo età
        if (Period.between(birthDate, LocalDate.now()).getYears() < 18) {
            return false;
        }
        
        // Controllo CF
        if (tableCF.contains(CF)) {
            return false;
        }
        
        // Aggiunta CF al database
        tableCF.add(CF);
        
        return true;
    }

    /**
     * @brief Il Server Reg si occupa di controllare e registrare tutti gli elettori legittimi
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        
        // Setting di KeyStore e TrustStore 
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreReg.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "register");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreReg.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "register");
        
        TableUserPass tableUserPass = new TableUserPass();
        HashSet<String> tableCF = new HashSet<>();
        
        // Inizializzazione di SReg in modalità server
        TLSServerBidi conn = new TLSServerBidi(7000);
        while (true) {
            SSLSocket socket = conn.accept();
            
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check = in.readUTF();
            System.out.println(check);
            
            if (check.equals("voter")) { // Connessione con Elettore
                if (!verifyAndSaveCF(tableCF, socket.getSession())) {
                    System.out.println("Il votante ha già recuperato le credenziali o non può votare");
                    out.writeInt(-1);
                } else {
                    out.writeInt(1);
                    
                    // Generazione e rilascio credenziali
                    UserPass credential = null;
                    do {     
                        credential = new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword());
                    } while (!tableUserPass.addUserPass(credential));
                    
                    out.writeObject(credential);
                    
                    System.out.println("Credenziali rilasciate");
                }
                
            } else if (check.equals("svoteCheck")) { // Connessione SVote per controllo credenziali
                if (conn.verifyIdentity(socket.getSession(), "CN=svote,OU=CEN,L=Campania")) {
                    UserPass toCheck = (UserPass) in.readObject();
                    String CF = in.readUTF();
                    out.writeBoolean(tableUserPass.containUserPass(toCheck) && tableCF.contains(CF));
                } else {
                    System.out.println("Error Svote identity");
                }
                
            } else if (check.equals("svoteSet")) { // Connessione SVote per inserimento firma
                if (conn.verifyIdentity(socket.getSession(), "CN=svote,OU=CEN,L=Campania")) {                    
                    UserPass toCheck = (UserPass) in.readObject();                    
                    SchnorrSig sign = (SchnorrSig) in.readObject();
                    
                    out.writeBoolean(tableUserPass.setSignature(toCheck, sign));
                } else {
                    System.out.println("Error Svote identity");
                }
                
            } else {
                System.out.println("Error command");
            }
            
            out.close();
            in.close();
            socket.close();
            
        }
    }
    
}
