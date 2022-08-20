/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ballotelections;

import utility.Schnorr;
import utility.SchnorrSig;

/**
 *
 * @author duino
 */
public class SchnorrTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        Schnorr signer = new Schnorr(64);
        
        String M = "Ciao";
        SchnorrSig sigma = signer.sign(M);

        // Verify
        System.out.println("Verification = " + Schnorr.verify(sigma, signer.getPK(), M));
    }
    
}
