/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utility;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 * @author duino
 */
public class ElGamalEnc {
    
    private final ElGamalPK PK;

    public ElGamalEnc(ElGamalPK PK) {
       this.PK=PK;
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
    
    
    
}
