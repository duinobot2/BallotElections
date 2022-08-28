package utility;

import java.io.Serializable;

/**
 * @author H¿ddεnBreakpoint
 * @brief Pacchetto contenente voto cifrato, firma e PK dell'elettore
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
