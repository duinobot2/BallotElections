/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import utility.SchnorrSig;
import utility.TLSServerBidi;
import utility.TableUserPass;
import utility.UserPass;
import utility.Utils;

/**
 *
 * @author duino
 */
public class SReg {

    public static boolean verifyAndSaveCF(HashSet<String> tableCF, SSLSession session) {
        return true;//saved
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        TableUserPass tableUserPass = new TableUserPass();
        HashSet<String> tableCF = new HashSet<>();

        TLSServerBidi conn = new TLSServerBidi(7000);
        while (true) {
            SSLSocket socket = conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check = in.readUTF();
            System.out.println(check);
            
            if (check.equals("voter")) {
                if (!verifyAndSaveCF(tableCF, socket.getSession())) {
                    System.out.println("Il votante ha già recuperato le credenziali o non può votare");
                    out.writeInt(-1);
                } else {
                    out.writeInt(1);
                    
                    UserPass credential = null;
                    do {
                        credential = new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword());
                    } while (!tableUserPass.addUserPass(credential));

                    out.writeObject(credential);
                                        
                    System.out.println("Credenziali rilasciate");
                }

            } else if (check.equals("svoteCheck")) {
               
                UserPass toCheck=(UserPass) in.readObject();
                
                out.writeBoolean(tableUserPass.containUserPass(toCheck));
                
                
            }else if (check.equals("svoteSet")) {
                              
                UserPass toCheck=(UserPass) in.readObject();
                             
                SchnorrSig sign = (SchnorrSig) in.readObject();
                
                out.writeBoolean(tableUserPass.setSignature(toCheck, sign));
            } else {
                System.out.println("Error command");
            }

            out.close();
            in.close();
            socket.close();

        }
    }

}
