/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servers;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalGen;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.PacketVote;
import utility.Schnorr;
import utility.TLSServerBidi;
import utility.Utils;

/**
 *
 * @author duino
 */
public class SUrna {
    
    private TLSServerBidi conn;
    private ElGamalPK PK;
    private ElGamalDec partialDec=null;
    ArrayList<PacketVote> packetVotes;

    public SUrna(int numPort, int secret) throws IOException, ClassNotFoundException {
        conn = new TLSServerBidi(numPort);
        packetVotes = new ArrayList<>();
        
        
        if(secret==1){
            SSLSocket socket = conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
        
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ElGamalGen tempGen = new ElGamalGen(64);
            ElGamalDec tempDec = new ElGamalDec(tempGen.getSK());

            out.writeObject(tempGen.getPK());

            int dim = in.readInt();

            byte[] SKbytes = new byte[dim];

            for(int i =0;i<dim;i++){
                SKbytes[i]=tempDec.decrypt((ElGamalCT)in.readObject()).byteValue();
            }

            partialDec = new ElGamalDec((ElGamalSK)Utils.byteArrayToObj(SKbytes));

            out.writeObject(partialDec.getPK());
            
            out.close();
            in.close();
            socket.close();
        }
        
        SSLSocket socket = conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        PK=(ElGamalPK) in.readObject();
        out.writeInt(1);
        
        out.close();
        in.close();
        socket.close();
    }
    

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
              
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter port number: ");
        int numPort = scan.nextInt();
        
        System.out.print("Enter getSecret? (1=yes): ");
        int secret = scan.nextInt();
        scan.close();
        
        SUrna urna = new SUrna(numPort,secret);
        
                       
        System.out.println("Sono pronto");
        
        
        
        
        while(true){
            SSLSocket socket = urna.conn.accept();
            //if(urna.conn.verifyIdentity(socket.getSession(), "CN=localhost,OU=Server,O=unisa,C=IT")){
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check=in.readUTF();
            if(check.equals("server")){    
                //ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                //ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                
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
                
            //}else if(urna.conn.verifyIdentity(socket.getSession(), "CN=localhost,OU=Client,O=unisa,C=IT")){
            }else if(check.equals("client")){    
                //ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                //ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                PacketVote p = (PacketVote) in.readObject();
                if(Schnorr.verify(p.getSign(), p.getSignPK(), Utils.toString(Utils.objToByteArray(p.getCT())))){
                    urna.packetVotes.add(p);
                    out.writeBoolean(true);
                }else
                    out.writeBoolean(false);

                System.out.println("Voto arrivato");

                out.close();
                in.close();
                socket.close();
            }else{
                System.out.println("Client malevolo");
            }
            
        }
        
        ElGamalCT finalCT = null;
        for(int i =0;i<urna.packetVotes.size();i++){
            if(i==0)
                finalCT=urna.packetVotes.get(i).getCT();
            else
                finalCT=ElGamalCT.Homomorphism(urna.PK, finalCT, urna.packetVotes.get(i).getCT());
        }
        
        System.out.println("Pronto ad inviare il CT");
        SSLSocket socket = urna.conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        out.writeObject(finalCT);
        System.out.println("inviatoCT");
        
        out.close();
        in.close();
        socket.close();

        
        if(secret==1){
            socket = urna.conn.acceptAndCheckClient("CN=localhost,OU=Client,O=unisa,C=IT");
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
    
}
