/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package testComponents;

import java.security.NoSuchAlgorithmException;
import utility.TableUserPass;
import utility.UserPass;
import utility.Utils;

/**
 *
 * @author duino
 */
public class UserPassTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // TODO code application logic here
        TableUserPass table = new TableUserPass();
        UserPass test= new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword());
        
        
        table.addUserPass(new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword()));
        table.addUserPass(new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword()));
        table.addUserPass(test);
        table.addUserPass(new UserPass(Utils.generatePassayPassword(), Utils.generatePassayPassword()));
        
        System.out.println(table.containUserPass(test)); //true
        test.setPassword(Utils.generatePassayPassword());
        System.out.println(table.containUserPass(test)); //false
        
    }
    
}
