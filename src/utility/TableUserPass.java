/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utility;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 *
 * @author duino
 */
public class TableUserPass {
    
    private class PassSign{
        private String pass;
        private String salt;
        private SchnorrSig sign;

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
    
    private HashMap<String, PassSign> tableUserPass = new HashMap<>();

    public TableUserPass() {
    }
    
    public boolean addUserPass(UserPass userPass) throws NoSuchAlgorithmException{
        if(tableUserPass.containsKey(userPass.getUsername()))
            return false;
        
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(salt);
        byte[] hashedPassword = md.digest(Utils.toByteArray(userPass.getPassword()));
        
        tableUserPass.put(userPass.getUsername(), new PassSign(Utils.toString(hashedPassword), Utils.toString(salt)));
        
        return true;
    }
    
    private PassSign getPassSign(UserPass userPass) throws NoSuchAlgorithmException{
        PassSign passSign = tableUserPass.get(userPass.getUsername());
        
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(Utils.toByteArray(passSign.salt));
        byte[] hashedPassword = md.digest(Utils.toByteArray(userPass.getPassword()));
        
        if(passSign!=null && passSign.getPass().equals(Utils.toString(hashedPassword)))
            return passSign;
        
        return null;
    }
    
    public boolean containUserPass(UserPass userPass) throws NoSuchAlgorithmException{
        PassSign passSign = getPassSign(userPass);
        
        return passSign != null;
    }
    
    public boolean setSignature(UserPass userPass, SchnorrSig sign) throws NoSuchAlgorithmException{
        PassSign passSign = getPassSign(userPass);
        if(passSign==null)
            return false;
        
        passSign.setSign(sign);
        
        return true;
    }
    
    public boolean isSigned(UserPass userPass) throws NoSuchAlgorithmException{
        PassSign passSign = getPassSign(userPass);
        return passSign.getSign()!=null;
    }
    
    

}
