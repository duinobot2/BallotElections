/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utility;

import java.io.Serializable;

/**
 *
 * @author En¿gma
 */
public class PacketVote implements Serializable{
    private ElGamalCT CT;
    private SchnorrSig sign;
    private SchnorrPK signPK;

    public PacketVote(ElGamalCT CT, SchnorrSig sign, SchnorrPK signPK) {
        this.CT = CT;
        this.sign = sign;
        this.signPK = signPK;
    }

    public ElGamalCT getCT() {
        return CT;
    }

    public SchnorrSig getSign() {
        return sign;
    }

    public SchnorrPK getSignPK() {
        return signPK;
    }
    
    
    
}
