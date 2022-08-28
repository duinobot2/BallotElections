package testComponents;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.util.encoders.Hex;
import utility.TableUserPass;
import utility.UserPass;
import utility.Utils;

/**
 *
 * @author H¿ddεnBreakpoint
 */
public class UserPassTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // TODO code application logic here
        TableUserPass table = new TableUserPass();
        UserPass test= new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword());
        System.out.println(test);
        
        table.addUserPass(new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword()));
        table.addUserPass(new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword()));
        table.addUserPass(test);
        table.addUserPass(new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword()));
        
        System.out.println(table.containUserPass(test)); //true
        test.setPassword(Utils.generatePassayPassword());
        System.out.println(table.containUserPass(test)); //false
        
        
        String hexString = "31362f30322f31393939";    
        System.out.println(new String(Hex.decode(hexString), "UTF-8"));
        
    }
    
}
