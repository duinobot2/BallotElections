package testComponents;

import java.io.IOException;
import utility.TLSClientBidi;

/**
 *
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 */
public class TLSTestClient {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException{
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", ".\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", ".\\src\\testComponents\\keystoreServer.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        
        TLSClientBidi client = new TLSClientBidi("localhost", 4000);
        
        System.out.println("Client Finished");
    }
    
}
