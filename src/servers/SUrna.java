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
 *
 * @author duino
 */
public class SUrna {
    
    private TLSServerBidi conn;
    private ElGamalPK PK;
    private ElGamalDec partialDec=null;
    ArrayList<PacketVote> packetVotes;

    public SUrna(int numPort) throws IOException, ClassNotFoundException {
        conn = new TLSServerBidi(numPort);
        packetVotes = new ArrayList<>();
        
        SSLSocket socket = conn.acceptAndCheckClient("CN=sdealer,OU=CEN,L=Campania");

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
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
        
        partialDec = new ElGamalDec((ElGamalSK)packet.getSK());

        out.writeObject(partialDec.getPK());

        out.close();
        in.close();
        socket.close();
        
        
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
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreUrna.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "servurna");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreUrna.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "servurna");
        
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter port number: ");
        int numPort = scan.nextInt();
        
        SUrna urna = new SUrna(numPort);
        
        System.out.println("Sono pronto");
        
        
        while(true){
            SSLSocket socket = urna.conn.accept();
            
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            String check=in.readUTF();
            if(check.equals("server")){    
                
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
            
            }else if(check.equals("client")){    
                
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
        
         TLSClientBidi SBacheca = new TLSClientBidi("localhost", 7001);
            
        ObjectOutputStream out = new ObjectOutputStream(SBacheca.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SBacheca.getcSock().getInputStream());
        ElGamalCT finalCT = null;
        
        out.writeUTF("surnaadd");
        out.flush();
        out.writeInt(urna.packetVotes.size());
        out.flush();
        
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
        
        System.out.println("Pronto ad inviare il CT");
        SSLSocket socket = urna.conn.acceptAndCheckClient("CN=sdecif,OU=CEN,L=Campania");
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        
        out.writeObject(finalCT);
        System.out.println("inviatoCT");
        
        out.close();
        in.close();
        socket.close();

        
        
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
