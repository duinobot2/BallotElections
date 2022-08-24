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
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalEnc;
import utility.ElGamalGen;
import utility.ElGamalPK;
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
                    ElGamalEnc tempEnc = new ElGamalEnc((ElGamalPK) in.readObject());
                    UserPass credential = null;
                    do {
                        credential = new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword());
                    } while (!tableUserPass.addUserPass(credential));

                    byte[] credToSend = Utils.objToByteArray(credential);
                    out.writeInt(credToSend.length);
                    for (int j = 0; j < credToSend.length; j++) {
                        byte[] temp = {0x00, credToSend[j]};
                        out.writeObject(tempEnc.encrypt(new BigInteger(temp)));//funziona con entrambe le encrypt con 0 a sx

                    }
                    
                    System.out.println("Credenziali rilasciate");
                }

            } else if (check.equals("svoteCheck")) {
                ElGamalGen tempGen = new ElGamalGen(64);
                ElGamalDec tempDec = new ElGamalDec(tempGen.getSK());

                out.writeObject(tempGen.getPK());

                int dim = in.readInt();

                byte[] userPassBytes = new byte[dim];

                for(int i =0;i<dim;i++){
                    userPassBytes[i]=tempDec.decrypt((ElGamalCT)in.readObject()).byteValue();
                }
                
                UserPass toCheck=(UserPass) Utils.byteArrayToObj(userPassBytes);
                
                out.writeBoolean(tableUserPass.containUserPass(toCheck));
                
                
            }else if (check.equals("svoteSet")) {
                ElGamalGen tempGen = new ElGamalGen(64);
                ElGamalDec tempDec = new ElGamalDec(tempGen.getSK());

                out.writeObject(tempGen.getPK());

                int dim = in.readInt();

                byte[] userPassBytes = new byte[dim];

                for(int i =0;i<dim;i++){
                    userPassBytes[i]=tempDec.decrypt((ElGamalCT)in.readObject()).byteValue();
                }
                
                UserPass toCheck=(UserPass) Utils.byteArrayToObj(userPassBytes);
                
                dim = in.readInt();
                
                byte[] signBytes = new byte[dim];
                
                for(int i =0;i<dim;i++){
                    signBytes[i]=tempDec.decrypt((ElGamalCT)in.readObject()).byteValue();
                }
                
                SchnorrSig sign = (SchnorrSig) Utils.byteArrayToObj(signBytes);
                
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
