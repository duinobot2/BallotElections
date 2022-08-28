package utility;

import java.math.BigInteger;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief Secret Key di Schnorr
 */
public class SchnorrSK {

    BigInteger s;
    SchnorrPK PK;

    public SchnorrSK(BigInteger s, SchnorrPK PK) {
        this.s = s;
        this.PK = PK;

    }
}
