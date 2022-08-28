package utility;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief Firma di Schnorr
 */
public class SchnorrSig implements Serializable{

    BigInteger a, e, z;

    public SchnorrSig(BigInteger a, BigInteger e, BigInteger z) {
        this.a = a;
        this.e = e;
        this.z = z;
    }

    @Override
    public String toString() {
        return "a=" + a + ", e=" + e + ", z=" + z ;
    }
    
    
}
