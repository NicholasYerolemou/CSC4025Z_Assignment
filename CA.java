import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
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

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Socket connectedClient = null;

    public CA() {
        generateKeys();
        listenForConnections();
    }

    private void generateKeys() {
        // generate this clients pub and private keys
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Unable to create key pair generator.");
            e.printStackTrace();
        }
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
        System.out.println("Listening for user input and messages.");

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
        } else if (message.equalsIgnoreCase("1")) {
            // Logic to check the public key against the client's certificate
        } else {
            // Handle unknown message
            System.out.println("Unknown message: " + message);
        }
    }

    private void issueCertificate() {
        PrintWriter outputStream = null;
        BufferedReader inputStream = null;
        try {
            outputStream = new PrintWriter(connectedClient.getOutputStream(), true);
            inputStream = new BufferedReader(new InputStreamReader(connectedClient.getInputStream()));

            // send the CA's public key to the client
            String pubKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String messageHash = calculateHash(pubKeyString);
            String message = pubKeyString + "," + messageHash;
            outputStream.println(message);

            String csrString = inputStream.readLine();
            byte[] csrBytes = Base64.getDecoder().decode(csrString);
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
            
            try {
                Boolean valid = csr.verify();

                if (valid) {
                    X509Certificate certificate = createCertificate(privateKey, csr);
                    byte[] certificateBytes = certificate.getEncoded();
                    String certificateString = Base64.getEncoder().encodeToString(certificateBytes);
                    outputStream.println(certificateString);
                    System.out.println("Certificate issued.");
                }
                else
                    System.out.println("Certificate sigining request invalid.");
            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (IOException | NoSuchAlgorithmException e) {

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

    //private void signCertificate() {
    //   return Null;
    //}

    private void sendMessage(String message, PrintWriter out) {
        out.println(message); // Send a message to the client
        try {
            connectedClient.close();
        } catch (IOException e) {
            System.out.println("Could not close connection with client.");
            e.printStackTrace();
        } // Close the connection after sending the response
    }

    private String calculateHash(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(message.getBytes());

        // Convert the byte array to a hexadecimal representation
        StringBuilder hexString = new StringBuilder();
        for (byte hashByte : hashBytes) {
            String hex = Integer.toHexString(0xff & hashByte);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        CA ca = new CA();
    }
}