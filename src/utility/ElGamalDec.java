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
public class ElGamalDec {
    
    private ElGamalSK SK;

    public ElGamalDec(ElGamalSK SK) {
        this.SK=SK;
        
    }
    
    public ElGamalPK getPK(){
        return SK.PK;
    }
    
    public BigInteger decryptInTheExponent(ElGamalCT CT) {
        BigInteger tmp = CT.C2.modPow(SK.s, SK.PK.p).modInverse(SK.PK.p);
        BigInteger res = tmp.multiply(CT.C).mod(SK.PK.p);
        // after this step res=g^d for some d in 1,...,q

        BigInteger M = new BigInteger("0");
        while (true) {
            if (SK.PK.g.modPow(M, SK.PK.p).compareTo(res) == 0) {
                return M;
            }
        // if g^M=res stop and return M
        // otherwise M++
            M = M.add(BigInteger.ONE);
        }

    }
    
    public ElGamalCT partialDecrypt(ElGamalCT CT) {
        // CT is the ciphertext to decrypt or a ciphertext resulting from a partial decryption
        // Suppose SK is the key of the i-th authority. Then SK.s is s_i
        BigInteger tmp = CT.C2.modPow(SK.s, SK.PK.p); // tmp=C2^s_i 
        tmp = tmp.modInverse(SK.PK.p);   // tmp=C2^{-s_i}
        BigInteger newC = tmp.multiply(CT.C).mod(SK.PK.p); // newC=C*tmp=(h^r*M)*C2^{-s_i}=h^r*M*g^{-rs_i}

        return new ElGamalCT(newC, CT.C2);
    }
    
    public BigInteger decrypt(ElGamalCT CT)
    {
    	// C=[C,C2]=[h^r*M mod p, g^r mod p].
    	// h=g^s mod p
    	
        BigInteger tmp = CT.C2.modPow(SK.s, SK.PK.p);  // tmp=C2^s mod p
        tmp=tmp.modInverse(SK.PK.p);  
        // if tmp and p are BigInteger tmp.modInverse(p) is the integer x s.t. 
        // tmp*x=1 mod p
        // thus tmp=C2^{-s}=g^{-rs} mod p =h^{-r}
        
        BigInteger M = tmp.multiply(CT.C).mod(SK.PK.p); // M=tmp*C mod p
    	return M; 
    	
    }
    
        
}
