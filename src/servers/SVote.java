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
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.util.encoders.Hex;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalEnc;
import utility.ElGamalGen;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.PacketVote;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.UserPass;
import utility.Utils;

/**
 *
 * @author duino
 */
public class SVote {

    /**
     * @param args the command line arguments
     */
    
    private static int countUrna=0;
    
    //spostare in votante
    public static PacketVote prepareVotePacket(int vote, ElGamalEnc enc, Schnorr signer) throws IOException{
        if(vote!=0 && vote!=1 && vote!=-1) return null;
        
        ElGamalCT CT = enc.encryptInTheExponent(BigInteger.valueOf(vote));
        
        SchnorrSig sign=signer.sign(Utils.toString(Utils.objToByteArray(CT)));
        
        return new PacketVote(CT, sign, signer.getPK());
    } 
    
    public static boolean sendPacketToUrna(PacketVote packet, int [] ports) throws IOException{
        if(Schnorr.verify(packet.getSign(), packet.getSignPK(), Utils.toString(Utils.objToByteArray(packet.getCT())))==false)
            return false;
        
        TLSClientBidi SUrna = new TLSClientBidi("localhost", ports[countUrna]);
        ObjectOutputStream out = new ObjectOutputStream(SUrna.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SUrna.getcSock().getInputStream());

        out.writeUTF("client");
        out.writeObject(packet);
        
        countUrna=(countUrna+1) % ports.length;
        boolean res=in.readBoolean();

        
        out.close();
        in.close();
        SUrna.getcSock().close();
        
        return res;
        
    }
    
    public static boolean checkUserPassCF(UserPass userPass, SSLSession session) throws IOException, ClassNotFoundException{
        X500Principal id = (X500Principal) session.getPeerPrincipal(); // getPeerPrincipal returns info about the X500Principal of the other peer
        // X500Principal is the field that contains country, Common Name, etc.
        System.out.println("principal: " + id.getName()); // print this info
        
        String[] strings = id.getName().split(",");
        String CF=null;
        
        for(String s : strings){
            if(s.startsWith("1.3.18.0.2.6.73")){
                CF=new String(Hex.decode(s.substring(21)));
                break;
            }
        }
        
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
        
        boolean response=in.readBoolean();
        
        out.close();
        in.close();
        SReg.getcSock().close();
        
        return response;
    }
    
    public static boolean setSignature(UserPass userPass, SchnorrSig sign) throws IOException, ClassNotFoundException{
        TLSClientBidi SReg = new TLSClientBidi("localhost", 7000);

        ObjectOutputStream out = new ObjectOutputStream(SReg.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SReg.getcSock().getInputStream());

        out.writeUTF("svoteSet");
        System.out.println("svoteSet send");
        out.flush();
        
        out.writeObject(userPass);
        out.flush();
        
        out.writeObject(sign);
        out.flush();
        
        boolean response=in.readBoolean();
        
        out.close();
        in.close();
        SReg.getcSock().close();
        
        return response;
    }
    
    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", ".\\cert\\keystoreVote.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "servvote");
        System.setProperty("javax.net.ssl.trustStore", ".\\cert\\truststoreVote.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "servvote");
        
        TLSServerBidi SDealer = new TLSServerBidi(5000);
        
        SSLSocket socket = SDealer.acceptAndCheckClient("CN=sdealer,OU=CEN,L=Campania");
        
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        ElGamalPK PK = (ElGamalPK)in.readObject();
        
        out.writeInt(1);
        
        out.close();
        in.close();
        socket.close();

        System.out.println("Sono Pronto");
        
        int[] ports= {4000, 4001, 4002};
        
        //accettazione votante e voto
        while(true){
            socket = SDealer.accept();
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            UserPass toCheck=(UserPass) in.readObject();
            System.out.println("tryTOCheckUserPass");
            boolean response = checkUserPassCF(toCheck, socket.getSession());
            
            out.writeBoolean(response);
            
            if(response){
           
                out.writeObject(PK);

                PacketVote p = (PacketVote) in.readObject();
                
                if(!setSignature(toCheck, p.getSign())){
                    out.writeBoolean(false);
                    System.out.println("Firma già presente");
                }else
                    out.writeBoolean(sendPacketToUrna(p, ports));
                    
                                        
                System.out.println("pacchetto inviato all'urna");
            }else
                System.out.println("Invalid UserPass");
            
            out.close();
            in.close();
            socket.close();
        }
        
        
    
    }
    
}
