package utility;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 * @author H¿ddεnBreakpoint
 * @brief Classe rappresentante il Database che conterrà: ID, Password Hashing, randomness usata per l'hashing, firma
 */
public class TableUserPass {
    
    // Classe Innestata rappresentante Password Hashing e Firma
    private class PassSign{
        private String pass; // password hashata
        private String salt; // randomness usata per l'hashing
        private SchnorrSig sign; //firma

        public PassSign(String pass,String salt) {
            this.pass = pass;
            this.salt = salt;
            this.sign = null;
        }

        public String getPass() {
            return pass;
        }

        public String getSalt() {
            return salt;
        }
        
        public SchnorrSig getSign() {
            return sign;
        }

        public void setSign(SchnorrSig sign) {
            this.sign = sign;
        }
        
        
        
    }
    
    private HashMap<String, PassSign> tableUserPass = new HashMap<>(); // La tabella contenente ID e PassSign

    public TableUserPass() {
    }
    
    /**
     * @brief Inserimento delle credenziali al database (se l'ID non è gia presente)
     * @param userPass coppia ID, password
     * @return true se va a buon fine l'inserimento, altrimenti false
     * @throws NoSuchAlgorithmException 
     */
    public boolean addUserPass(UserPass userPass) throws NoSuchAlgorithmException{
        if(tableUserPass.containsKey(userPass.getUsername()))
            return false;
        
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] hashedPassword = md.digest(Utils.toByteArray(userPass.getPassword()));
        
        tableUserPass.put(userPass.getUsername(), new PassSign(Utils.toString(hashedPassword), Utils.toString(salt)));
        
        return true;
    }
    
    /**
     * @brief Hashing della password
     * @param userPass coppia ID, password
     * @return password hashata come oggetto PassSign
     * @throws NoSuchAlgorithmException 
     */
    private PassSign getPassSign(UserPass userPass) throws NoSuchAlgorithmException{
        PassSign passSign = tableUserPass.get(userPass.getUsername());
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Utils.toByteArray(passSign.salt));
        byte[] hashedPassword = md.digest(Utils.toByteArray(userPass.getPassword()));
        
        if(passSign!=null && passSign.getPass().equals(Utils.toString(hashedPassword)))
            return passSign;
        
        return null;
    }
    
    /**
     * @brief Verifica della presenza di ID e password nel database
     * @param userPass coppia ID e password
     * @return true se la coppia è presente, altrimenti false
     * @throws NoSuchAlgorithmException 
     */
    public boolean containUserPass(UserPass userPass) throws NoSuchAlgorithmException{
        PassSign passSign = getPassSign(userPass);
        
        return passSign != null;
    }
    
    /**
     * @brief Inserimento della firma nel database nella riga corrispondente a userPass
     * @param userPass coppia ID e password
     * @param sign firma da inserire
     * @return true se la firma è stata inserita con successo, altrimenti false
     * @throws NoSuchAlgorithmException 
     */
    public boolean setSignature(UserPass userPass, SchnorrSig sign) throws NoSuchAlgorithmException{
        PassSign passSign = getPassSign(userPass);
        if(passSign==null || passSign.getSign() == null)
            return false;
        
        passSign.setSign(sign);
        
        return true;
    }
    
}
