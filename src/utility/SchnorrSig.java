package utility;

import java.io.Serializable;
import java.math.BigInteger;

public class SchnorrSig implements Serializable{

    BigInteger a, e, z;

    public SchnorrSig(BigInteger a, BigInteger e, BigInteger z) {
        this.a = a;
        this.e = e;
        this.z = z;
    }
}
