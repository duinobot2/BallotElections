/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import javax.net.ssl.SSLSocket;
import utility.SchnorrSig;
import utility.TLSServerBidi;

/**
 *
 * @author duino
 */
public class SBacheca {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreBacheca.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "bacheca");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreBacheca.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "bacheca");
        
        ArrayList<SchnorrSig> signatureList = new ArrayList<>();
        TLSServerBidi conn = new TLSServerBidi(7001);
        
        while (true) {
            SSLSocket socket = conn.accept();

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check = in.readUTF();
            System.out.println(check);
            
            if (check.equals("surnaadd")) {
                if(conn.verifyIdentity(socket.getSession(), "CN=surna,OU=CEN,L=Campania")){
                    int numSign=in.readInt();
                    for(int i=0;i<numSign;i++)
                        signatureList.add((SchnorrSig) in.readObject());
                }else
                    System.out.println("Error SUrna identity");
                
                out.close();
                in.close();
                socket.close();
            }else if(check.equals("stop")){
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
        
        System.out.println("Stampa bacheca:");
        for(SchnorrSig sig : signatureList){
            System.out.println(sig);
        }
    }
    
}
