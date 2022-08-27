/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utility;

import java.io.Serializable;

/**
 *
 * @author duino
 */
public class PacketShareSK implements Serializable{
     private ElGamalSK SK;
    private SchnorrSig sign;
    private SchnorrPK signPK;

    public PacketShareSK(ElGamalSK SK, SchnorrSig sign, SchnorrPK signPK) {
        this.SK = SK;
        this.sign = sign;
        this.signPK = signPK;
    }

    public ElGamalSK getSK() {
        return SK;
    }

    public SchnorrSig getSign() {
        return sign;
    }

    public SchnorrPK getSignPK() {
        return signPK;
    }
}
