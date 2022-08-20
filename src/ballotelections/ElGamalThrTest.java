/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ballotelections;

import java.math.BigInteger;
import utility.ElGamalCT;
import static utility.ElGamalCT.Homomorphism;
import utility.ElGamalDec;
import utility.ElGamalEnc;
import utility.ElGamalGen;
import utility.ElGamalPK;
import utility.ElGamalSK;

/**
 *
 * @author duino
 */
public class ElGamalThrTest {
    
    

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        ElGamalGen generator = new ElGamalGen(64);
        ElGamalDec[] urna = new ElGamalDec[3];
        
        for(int i=0;i<3;i++)
            urna[i]=new ElGamalDec(generator.getPartialSecret());
        
        ElGamalPK[] PKs= new ElGamalPK[3];
        
        for(int i=0;i<3;i++)
            PKs[i]=urna[i].getPK();
        
        ElGamalPK PK = generator.aggregatePartialPublicKeys(PKs);
        
        ElGamalEnc voter1 = new ElGamalEnc(PK);
        ElGamalEnc voter2 = new ElGamalEnc(PK);
        
        BigInteger M1, M2; // Encryption done by Voter1 and Voter2
        M1 = new BigInteger("24"); // Voter1 encrypts 24
        M2 = new BigInteger("14"); // Voter2 encrypts 14
        
        ElGamalCT CT1 = voter1.encryptInTheExponent(M1); // CT1 encrypts 24
        ElGamalCT CT2 = voter2.encryptInTheExponent(M2); // CT2 encrypts 14
        
        ElGamalCT CTH = Homomorphism(PK, CT1, CT2); // CTH encrypts the sum of the plaintexts in CT1 and CT2 that is 24+14
        
        ElGamalCT DecCT=CTH;
        
        for(int i=0;i<2;i++)
            DecCT=urna[i].partialDecrypt(DecCT);
        
        BigInteger D = urna[2].decryptInTheExponent(DecCT); // finally the third authority
        // uses the standard decryption procedure to recover the message
        System.out.println("decrypted plaintext with threshold El Gamal = " + D + "\n"); // it should print the same integer as before

        
        
    }
    
}
