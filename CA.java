import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Time;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class CA {

    private KeyPair keyPair;
    private Socket connectedClient = null;
    private X509Certificate selfSignedCert;

    public CA() {
        generateKeys();
        createSelfCert();
        listenForConnections();
    }

    private void generateKeys() {
        // generate this clients keypair
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Unable to create key pair generator.");
            e.printStackTrace();
        }
    }


    private void createSelfCert() {
        
            X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
            
            // Set certificate attributes
            certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            certGen.setIssuerDN(new X500Principal("CN=CA"));
            certGen.setNotBefore(new Date(System.currentTimeMillis()));
            certGen.setNotAfter(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L)); // 1 year validity
            certGen.setSubjectDN(new X500Principal("CN=CA"));
            certGen.setPublicKey(keyPair.getPublic());
            certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

            // Create a self-signed certificate
            try 
            {
                selfSignedCert = certGen.generate(keyPair.getPrivate(), "BC");
            }
            catch (CertificateEncodingException | NoSuchProviderException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e)
            {
                System.out.println("Error creating self signed certificate.");
                e.printStackTrace();
            }
            System.out.println("Created self-signed certificate");


        

    }


    private void listenForConnections() {
        int PORT = 12346;
        try {
            ServerSocket CASocket = new ServerSocket(PORT);
            System.out.println("The CA is listening on port " + PORT);

            while (true) {
                Socket targetSocket = CASocket.accept();
                connectedClient = targetSocket;
                System.out.println("Client connected from " + targetSocket.getInetAddress().getHostAddress() + ".");

                listenForMessages();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void listenForMessages() {
        System.out.println("Listening for messages.");

        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(connectedClient.getInputStream()));
            PrintWriter out = new PrintWriter(connectedClient.getOutputStream(), true);
            String receivedMessage = in.readLine();

            if (receivedMessage != null) {
                receiveMessage(receivedMessage, out);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void receiveMessage(String message, PrintWriter out) {
        if (message.equalsIgnoreCase("0")) {
            System.out.println("Client requested a new certificate.");
            issueCertificate();
        } 
        else {

            System.out.println("Unknown message: " + message);
        }
    }

    private void issueCertificate() {
        PrintWriter outputStream = null;
        BufferedReader inputStream = null;
        try {
            outputStream = new PrintWriter(connectedClient.getOutputStream(), true);
            inputStream = new BufferedReader(new InputStreamReader(connectedClient.getInputStream()));
            byte[] message = selfSignedCert.getEncoded();
            String encodedMessage = Base64.getEncoder().encodeToString(message);
            outputStream.println(encodedMessage);

           
            //get the CSR rom the client
            String csrString = inputStream.readLine();
            byte[] csrBytes = Base64.getDecoder().decode(csrString);
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

            
            if (csr.verify()) {
                X509Certificate certificate = createCertificate(keyPair.getPrivate(), csr);
                byte[] certificateBytes = certificate.getEncoded();
                String certificateString = Base64.getEncoder().encodeToString(certificateBytes);
                outputStream.println(certificateString);
                System.out.println("Certificate issued.");
            }
            else
                System.out.println("Certificate sigining request invalid.");
                outputStream.println("Invalid CSR");

            
           
        } 
        catch (IOException | CertificateEncodingException | NoSuchAlgorithmException |NoSuchProviderException | InvalidKeyException |SignatureException e) {

            e.printStackTrace();
        }

    }

    private X509Certificate createCertificate(PrivateKey privateKey, PKCS10CertificationRequest csr) {
        try { 
            X509V1CertificateGenerator  certificate = new X509V1CertificateGenerator();

            certificate.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            certificate.setIssuerDN(new X500Principal("CN=CA"));
            certificate.setNotBefore(new Date(System.currentTimeMillis()));
            certificate.setNotAfter(new Date(System.currentTimeMillis() + 24 * 3600 * 1000L)); // set the validity period of the certificate to one day
            certificate.setSubjectDN(new X500Principal(csr.getCertificationRequestInfo().getSubject().toString()));
            certificate.setPublicKey(csr.getPublicKey());
            certificate.setSignatureAlgorithm("SHA256WithRSAEncryption");

            X509Certificate clientCert = certificate.generateX509Certificate(privateKey); // signs the certificate with the CA private key
            return clientCert;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        CA ca = new CA();
    }
}