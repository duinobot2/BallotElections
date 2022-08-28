package utility;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief Threshold El Gamal Encryption
 */
public class ElGamalEnc {

    private final ElGamalPK PK;

    public ElGamalEnc(ElGamalPK PK) {
        this.PK = PK;
    }

    public ElGamalPK getPK() {
        return PK;
    }

    public ElGamalCT encryptInTheExponent(BigInteger m) {
        // identical to Encrypt except that input is an exponent m and encrypts M=g^m mod p

        SecureRandom sc = new SecureRandom();
        BigInteger M = PK.g.modPow(m, PK.p); // M=g^m mod p
        BigInteger r = new BigInteger(PK.securityparameter, sc);
        BigInteger C = M.multiply(PK.h.modPow(r, PK.p)).mod(PK.p);
        BigInteger C2 = PK.g.modPow(r, PK.p);
        return new ElGamalCT(C, C2);

    }

    public ElGamalCT encrypt(BigInteger M) {
        SecureRandom sc = new SecureRandom(); // create a secure random source

        BigInteger r = new BigInteger(PK.securityparameter, sc); // choose random r of lenght security parameter
        // C=[h^r*M mod p, g^r mod p].

        BigInteger C = M.multiply(PK.h.modPow(r, PK.p)); // C=M*(h^r mod p)
        C = C.mod(PK.p); // C=C mod p
        BigInteger C2 = PK.g.modPow(r, PK.p);  // C2=g^r mod p
        return new ElGamalCT(C, C2);   // return CT=(C,C2)

    }

}
