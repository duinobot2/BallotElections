package utility;

import java.math.BigInteger;

public class SchnorrPK {

    BigInteger g, h, p, q;
    int securityparameter;

    public SchnorrPK(BigInteger p, BigInteger q, BigInteger g, BigInteger h, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.h = h;
        this.securityparameter = securityparameter;

    }
}
