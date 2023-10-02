import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

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

            createCertificate();
            // CA recieves the CSR from the client
            // Verify the CSR using bouncy castle methods
            // create certificate baed on the CSR
            // return the certificate

        } catch (IOException | NoSuchAlgorithmException e) {

            e.printStackTrace();
        }

    }

    private void createCertificate() {
        // Logic to create a new certificate for the client
        System.out.println("Certificate issued.");

    }

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
        CA ca = new CA();
    }
}
