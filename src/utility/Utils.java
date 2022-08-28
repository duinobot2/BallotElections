package utility;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import static org.passay.AllowedCharacterRule.ERROR_CODE;
import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordGenerator;

/**
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 * @brief Classe contenente metodi statici utili
 */
public class Utils {

    /**
     * @brief Conversione di un certo numero di byte di un array in Stringa
     * @param bytes array di byte da convertire
     * @param length lunghezza array di byte
     * @return stringa
     */
    public static String toString(
            byte[] bytes,
            int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    /**
     * @brief Conversione array di byte in Stringa
     * @param bytes array di byte da convertire
     * @return stringa
     */
    public static String toString(
            byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    /**
     * @brief Conversione di un oggetto in un array di byte
     * @param obj oggetto da convertire
     * @return array di byte
     * @throws IOException 
     */
    public static byte[] objToByteArray(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = null;
        byte[] yourBytes;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(obj);
            out.flush();
            yourBytes = bos.toByteArray();

        } finally {
            bos.close();
        }

        return yourBytes;
    }

    /**
     * @brief Conversione di un array di byte in un oggetto
     * @param bytes array di byte da convertire
     * @return oggetto
     * @throws IOException
     * @throws ClassNotFoundException 
     */
    public static Object byteArrayToObj(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInput in = null;
        Object o = null;
        try {
            in = new ObjectInputStream(bis);
             o = in.readObject();
        } finally {

            if (in != null) {
                in.close();
            }
        }
        return o;
    }
    
    /**
     * @brief Generazione di una stringa casuale rappresentante Password/ID (con randomness sicura) 
     * @return stringa casuale
     */
    public static String generatePassayPassword() {
        PasswordGenerator gen = new PasswordGenerator(new SecureRandom());
        CharacterData lowerCaseChars = EnglishCharacterData.LowerCase;
        CharacterRule lowerCaseRule = new CharacterRule(lowerCaseChars);
        lowerCaseRule.setNumberOfCharacters(2);

        CharacterData upperCaseChars = EnglishCharacterData.UpperCase;
        CharacterRule upperCaseRule = new CharacterRule(upperCaseChars);
        upperCaseRule.setNumberOfCharacters(2);

        CharacterData digitChars = EnglishCharacterData.Digit;
        CharacterRule digitRule = new CharacterRule(digitChars);
        digitRule.setNumberOfCharacters(2);

        CharacterData specialChars = new CharacterData() {
            public String getErrorCode() {
                return ERROR_CODE;
            }

            public String getCharacters() {
                return "!@#$%^&*()_+";
            }
        };
        CharacterRule splCharRule = new CharacterRule(specialChars);
        splCharRule.setNumberOfCharacters(2);

        String password = gen.generatePassword(10, splCharRule, lowerCaseRule, upperCaseRule, digitRule);
        return password;
    }

}
