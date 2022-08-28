package utility;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief Struttura del ciphertext El Gamal
 */

public class ElGamalCT implements Serializable {

    BigInteger C, C2;

    public ElGamalCT(BigInteger C, BigInteger C2) {
        this.C = C;
        this.C2 = C2;

    }

    public ElGamalCT(ElGamalCT CT) {
        this.C = CT.C;
        this.C2 = CT.C2;

    }
    
    /**
     * @brief Variante di El Gamal che sfrutta l'omomorfismo
     * @param PK Public Key aggregata
     * @param CT1 ciphertext 1
     * @param CT2 ciphertext 2
     * @return ciphertext aggregato
     */
    public static ElGamalCT Homomorphism(ElGamalPK PK, ElGamalCT CT1, ElGamalCT CT2) {
        ElGamalCT CT = new ElGamalCT(CT1); // CT=CT1
        CT.C = CT.C.multiply(CT2.C).mod(PK.p);  // CT.C=CT.C*CT2.C mod p
        CT.C2 = CT.C2.multiply(CT2.C2).mod(PK.p); // CT.C2=CT.C2*CT2.C2 mod p
        return CT; // If CT1 encrypts m1 and CT2 encrypts m2 then CT encrypts m1+m2

    }

    @Override
    public String toString() {
        return "ElGamalCT{" + "C=" + C + ", C2=" + C2 + '}';
    }

}
