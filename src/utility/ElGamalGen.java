package utility;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief El Gamal Key Pair Generation
 */
public class ElGamalGen {
    private ElGamalSK SK;

    public ElGamalGen(int securityparameter) {
        BigInteger p, q, g, h;

        SecureRandom sc = new SecureRandom(); // create a secure random source

        while (true) {
            q = BigInteger.probablePrime(securityparameter, sc);
            // method probablePrime returns a prime number of length securityparameter
            // using sc as random source

            p = q.multiply(BigInteger.valueOf(2));
            p = p.add(BigInteger.ONE);  // p=2q+1

            if (p.isProbablePrime(50) == true) {
                break;		// returns an integer that is prime with prob.
            }// 1-2^-50

        }
        // henceforth we have that p and q are both prime numbers and p=2q+1
        // Subgroups of Zp* have order 2,q,2q

        g = new BigInteger("4"); // 4 is quadratic residue so it generates a group of order q
        // g is a generator of the subgroup the QR modulo p
        // in particular g generates q elements where q is prime

        BigInteger s = new BigInteger(securityparameter, sc); // s is the secret-key
        h = g.modPow(s, p); // h=g^s mod p

        ElGamalPK PK = new ElGamalPK(p, q, g, h, securityparameter);

        SK = new ElGamalSK(s, PK);
    }

    public ElGamalSK getSK() {
        return SK;
    }
    
    public ElGamalPK getPK(){
        return SK.PK;
    }
    
    public ElGamalSK getPartialSecret(){
        SecureRandom sc = new SecureRandom();
        BigInteger s = new BigInteger(SK.PK.securityparameter, sc); // i-th authority has s_i
        BigInteger h = SK.PK.g.modPow(s, SK.PK.p); // and h_i=g^{s_i}

        ElGamalPK PK = new ElGamalPK(SK.PK.p, SK.PK.q, SK.PK.g, h, SK.PK.securityparameter); //
        
        // return the partial public key of i-th authority
        return new ElGamalSK(s, PK);
    }
    
    public ElGamalPK aggregatePartialPublicKeys(ElGamalPK PK[]) {

        BigInteger tmp = BigInteger.ONE;
        // the array PK contains the partial public keys of the m-authorities
        // in particular PK[i].h=h_i=g^{s_i}

        for (int i = 0; i < PK.length; i++) {
            tmp = tmp.multiply(PK[i].h).mod(PK[0].p);
        }
        // here tmp=\Prod_{i=1}^m h_i
        // therefore tmp is the General public key h
        return new ElGamalPK(PK[0].p, PK[0].q, PK[0].g, tmp, PK[0].securityparameter);

    }
    
}
