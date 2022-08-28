package utility;

import java.io.Serializable;

/**
 * @author H¿ddεnBreakpoint
 * @brief Pacchetto contenente le share della SK
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
