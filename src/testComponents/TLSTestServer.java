package testComponents;

import java.io.IOException;
import utility.TLSServerBidi;

/**
 *
 * @author H¿ddεnBreakpoint (feat. Vincenzo Iovino)
 */
public class TLSTestServer {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException{
        // TODO code application logic here
        System.setProperty("javax.net.ssl.keyStore", ".\\src\\testComponents\\keystoreServer.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", ".\\src\\testComponents\\keystoreClient.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        TLSServerBidi server = new TLSServerBidi(4000);
        
        server.acceptAndCheckClient("");
        
    }
    
}
