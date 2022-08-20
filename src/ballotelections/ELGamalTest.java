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

/**
 *
 * @author duino
 */
public class ELGamalTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        ElGamalGen generator = new ElGamalGen(64);
        ElGamalDec urna = new ElGamalDec(generator.getSK());
        ElGamalEnc voter1 = new ElGamalEnc(generator.getPK());
        ElGamalEnc voter2 = new ElGamalEnc(generator.getPK());
        
        BigInteger M1, M2; // Encryption done by Voter1 and Voter2
        M1 = new BigInteger("24"); // Voter1 encrypts 24
        M2 = new BigInteger("14"); // Voter2 encrypts 14
        
        ElGamalCT CT1 = voter1.encryptInTheExponent(M1); // CT1 encrypts 24
        ElGamalCT CT2 = voter2.encryptInTheExponent(M2); // CT2 encrypts 14
        
        ElGamalCT CTH = Homomorphism(urna.getPK(), CT1, CT2); // CTH encrypts the sum of the plaintexts in CT1 and CT2 that is 24+14
        
        BigInteger D;
        D = urna.decryptInTheExponent(CTH);
        System.out.println("decrypted plaintext with Exponential El Gamal= " + D); // it should be 38

        
    }
    
}
