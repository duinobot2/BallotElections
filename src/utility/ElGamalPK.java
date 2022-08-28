package utility;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief El Gamal Public Key
 */
public class ElGamalPK implements Serializable {

    BigInteger g, h, p, q; // description of the group and public-key h=g^s
    int securityparameter; // security parameter

    public ElGamalPK(BigInteger p, BigInteger q, BigInteger g, BigInteger h, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.h = h;
        this.securityparameter = securityparameter;

    }
}
