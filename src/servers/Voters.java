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
 *
 * @author duino
 */
public class Voters {

        
    public static PacketVote prepareVotePacket(int vote, ElGamalEnc enc, Schnorr signer) throws IOException{
        if(vote!=0 && vote!=1 && vote!=-1) return null;
        
        ElGamalCT CT = enc.encryptInTheExponent(BigInteger.valueOf(vote));
        
        SchnorrSig sign=signer.sign(Utils.toString(Utils.objToByteArray(CT)));
        
        return new PacketVote(CT, sign, signer.getPK());
    }
    
    private static UserPass getUserPass() throws IOException, ClassNotFoundException {
        TLSClientBidi SReg = new TLSClientBidi("localhost", 7000);

        ObjectOutputStream out = new ObjectOutputStream(SReg.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SReg.getcSock().getInputStream());

        out.writeUTF("voter");
        out.flush();

        int dim = in.readInt();
        if(dim==-1)
            return null;
        
        UserPass userPass = (UserPass) in.readObject();

        out.close();
        in.close();
        SReg.getcSock().close();
        
        return userPass;
    }
    
    private static boolean vote(UserPass userPass, int vote) throws IOException, ClassNotFoundException{
        TLSClientBidi SVote = new TLSClientBidi("localhost", 5000);

        ObjectOutputStream out = new ObjectOutputStream(SVote.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(SVote.getcSock().getInputStream());
        
        out.writeObject(userPass);
        out.flush();
        
        if(!in.readBoolean()){
            System.out.println("Errore userPass errate");
            return false;
        }
        
        ElGamalEnc enc = new ElGamalEnc((ElGamalPK) in.readObject());
        Schnorr signer = new Schnorr(64);
        
        PacketVote p = prepareVotePacket(vote, enc, signer);
        
        out.writeObject(p);
        
        boolean response=in.readBoolean();
        
        out.close();
        in.close();
        SVote.getcSock().close();
        
        return response;
        
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        System.setProperty("javax.net.ssl.keyStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", "D:\\duino\\Google Drive (antonello.avella@iisfocaccia.edu.it)\\2022\\AlgeProtSicurezza\\ProjectElections\\BallotElections\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
        System.out.println("Responso votanti:");
        System.out.println(vote(getUserPass(), 1));
        System.out.println(vote(getUserPass(), 0));
        System.out.println(vote(getUserPass(), 1));
        System.out.println(vote(getUserPass(), -1));
        System.out.println(vote(getUserPass(), 0));
        System.out.println(vote(getUserPass(), 1));
        
        UserPass error= getUserPass();
        error.setPassword("resfsddf");
        
        System.out.println(vote(error, 1));
        
    }

}
