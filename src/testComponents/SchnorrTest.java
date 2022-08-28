package testComponents;

import utility.Schnorr;
import utility.SchnorrSig;

/**
 *
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 */
public class SchnorrTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        Schnorr signer = new Schnorr(256);
        
        String M = "Ciao";
        SchnorrSig sigma = signer.sign(M);
        
        // Verify
        System.out.println("Verification = " + Schnorr.verify(sigma, signer.getPK(), M));
    }
    
}
