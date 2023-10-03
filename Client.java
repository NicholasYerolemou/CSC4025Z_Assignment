import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class Client {

    static Client client;
    SecretKey sessionKey;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    private KeyPair keyPair;
    private static boolean connected = false;
    private Socket targetSocket = null;// the socket if the client you are connected to
    private String username;

    public Client(String name) {

        username = name;
        if (name.equalsIgnoreCase("Alice")) {
            generateKeys();
            getCertificate();
            connectAsServer();
        } else if (name.equalsIgnoreCase("Bob")) {
            generateKeys();
            getCertificate();
            connectAsClient();
        } else {
            System.out.println("Not a valid username. Enter either Alice or Bob");
        }

    }

    private void generateKeys() {
        // generate this clients pub and private keys
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

    private void getCertificate() {
        // connect to the CA and request a new certificate
        Socket CA_Socket = connectToCA();
        if (CA_Socket != null) {
            System.out.println("Connected to CA.");
            // request new certificate
            // we may need to first establish a secure channel

            PrintWriter outputStream = null;
            BufferedReader inputStream = null;

            try {
                System.out.println("Requesting certificate.");

                outputStream = new PrintWriter(CA_Socket.getOutputStream(), true);
                inputStream = new BufferedReader(new InputStreamReader(CA_Socket.getInputStream()));
                // request certificate
                outputStream.println("0");

                // get CAs public key
                String recievedMessage = inputStream.readLine();
                String[] data = recievedMessage.split(",");
                String CA_publicKeyString = data[0];
                String messageHash = data[1];

                if (verifyHash(CA_publicKeyString, messageHash)) {

                    byte[] CA_publicKeyBytes = Base64.getDecoder().decode(CA_publicKeyString);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(CA_publicKeyBytes);
                    PublicKey CA_PublicKey = keyFactory.generatePublic(publicKeySpec);

                    // Create a CSR certificate signing request using
                    // PKCS10CertificationRequestBuilder in bouncy castle
                    // Sign CSR with your private key
                    // Send to CA who will verify the CSR and then sign your public key and other
                    // relevant information with their private key, creating a digital certificate.
                    // They send the digital certificate back to you

                    System.out.println("Certificate recieved.");

                } else {
                    System.out.println("The hash recieved did not match the CAs public key.");
                }

            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {

                e.printStackTrace();
            }

        } else {
            System.out.println("Unable to connect to CA.");

        }

    }

    private Socket connectToCA() {
        int CA_PORT = 12346;// CA's port number
        String CA_ADDRESS = "127.0.0.1";
        Socket CA_Socket = null;
        try {
            CA_Socket = new Socket(CA_ADDRESS, CA_PORT);
        } catch (IOException e) {
            System.out.println("Unable to connect to CA. Attempting again in 5 seconds.");
            // this doesnt work properly yet
            try {
                Thread.sleep(5000);
                connectToCA();
            } catch (InterruptedException e1) {
                e1.printStackTrace();
            }
        }
        return CA_Socket;

    }

    private void connectAsServer() {
        // initializes connection and waits for bob to connect
        int PORT = 12345;
        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            // the socket this client is listening for connections on
            System.out.println("Listening on port " + PORT);

            // Accept incoming client connections
            targetSocket = serverSocket.accept();
            // the socket of the client we are connected to
            System.out.println("Client connected from " + targetSocket.getInetAddress().getHostAddress() + ".");
            connected = true;
            createSession();
            listenForUserInput();
            listenForMessages();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void connectAsClient() {
        int PORT = 12345;
        String SERVER_ADDRESS = "127.0.0.1"; // Change this to Alice's server address if needed

        try {

            targetSocket = new Socket(SERVER_ADDRESS, PORT);
            // the socket of the client we are connected to
            System.out.println("Connected to client at " + SERVER_ADDRESS + ":" + PORT);
            connected = true;
            createSession();
            listenForUserInput();
            listenForMessages();

            // socket.close();
        } catch (IOException e) {
            System.err.println("Error connecting to other client: " + e.getMessage());
        }
    }

    private void createSession() {
        // called after a connection is established
        // exchange certificates and generate session key
        // then begin listening

        System.out.println("Creating session.");
        PrintWriter outputStream = null;
        BufferedReader inputStream = null;
        String response;
        try {

            outputStream = new PrintWriter(targetSocket.getOutputStream(), true);
            outputStream.println("Your certificate goes here");// send your certificate here
            inputStream = new BufferedReader(new InputStreamReader(targetSocket.getInputStream()));// get response from
                                                                                                   // client
            response = inputStream.readLine();
            boolean verified = verifyCertificate(response);
            verified = true;
            // The response should contain their certificate

            if (verified) {
                if (username.equalsIgnoreCase("Alice")) {

                    // generate session key
                    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                    keyGenerator.init(128);
                    sessionKey = keyGenerator.generateKey();

                    // convert to string
                    String sessionKeyString = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
                    String sessionKeyhashString = calculateHash(sessionKeyString);

                    // send message
                    String message = sessionKeyString + "," + sessionKeyhashString;
                    outputStream.println(message);

                } else if (username.equalsIgnoreCase("Bob")) {
                    // Simulate receiving the session key and its hash from Alice

                    String message = inputStream.readLine();
                    String[] data = message.split(",");
                    String sessionKeyString = data[0];
                    String sessionKeyHash = data[1];

                    if (verifyHash(sessionKeyString, sessionKeyHash)) {

                        byte[] receivedSessionKeyBytes = Base64.getDecoder().decode(sessionKeyString);
                        sessionKey = new SecretKeySpec(receivedSessionKeyBytes, "AES");
                    } else {
                        System.out.println("Session key recieved does not match message hash.");
                        // resend message requesting session key
                    }

                }

                // encode session key with our private key
                // ecnode session key with their public key
                // send session key
                // store session key locally
            }

            System.out.println("Session created.");

        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Failed to create writer to client" + e.getMessage());
        }
    }

    private boolean verifyCertificate(String recievedCertificate) {
        return true;// return true if the certificate is verified, false otherwise
        // store their public key on our system
        // To verify - check if it can be decrypted by the CA's public key
    }

    private void listenForUserInput() {
        // Create another thread to listen for user input to trigger sending a message.

        Thread userListenerThread = new Thread(() -> {
            System.out.println("Listening for user input.");
            System.out.println(this);
            GUI gui = new GUI(this);
            // Create output stream
            // PrintWriter out = null;

            // try {

            //     out = new PrintWriter(targetSocket.getOutputStream(), true);
            // } catch (IOException e) {
            //     System.out.println("Failed to create writer to client" + e.getMessage());
            // }

            // while (connected) {
            //     // listen for user input
            //     Scanner scanner = new Scanner(System.in);
            //     String userInput = scanner.nextLine();
            //     sendMessage(userInput, out);

            // }
        });
        userListenerThread.start();

    }

    private void listenForMessages() {
        System.out.println("Listening for incoming messages.");

        // listen for a recieved input to trigger processing a message.

        // Create input and output streams
        BufferedReader in = null;

        try {
            in = new BufferedReader(new InputStreamReader(targetSocket.getInputStream()));
        } catch (IOException e) {
            System.out.println("Failed to create reader to client" + e.getMessage());
        }

        while (connected) {

            // Receive messages
            String receivedMessage;
            try {
                receivedMessage = in.readLine();

                if (receivedMessage == null) {
                    // the other client has disconnected
                    connected = false;
                    System.out.println("Connected set to: " + connected);
                } else {
                    recieveMessage(receivedMessage);
                }

            } catch (IOException e) {
                System.out.print("error");
                e.printStackTrace();
            }

        }

    }

    public void sendMessage(String message) {
       PrintWriter outputStream;
    try {
        outputStream = new PrintWriter(targetSocket.getOutputStream(), true);
         System.out.println("Message sent: " + message + ".");
        outputStream.println(message); // Send a message
    } catch (IOException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }

        // process the outgoing message here

        // encode message (message is the image) to a string
        // hash message
        // create combination of message and hash
        // use session key to encrypt it all
        // send it to the client
       
    }

    private void recieveMessage(String message) {
        // Process the incoming message here
        // use session key to decrypt the message
        // Remove hash from message
        // compue hash on message without hash compare with hash
        // decode the message
        // display/print out the message
        System.out.println("Message Recieved: " + message);
    }

    private String encodeImageToString(String imagePath) throws IOException {
        File imageFile = new File(imagePath);
        FileInputStream imageInputStream = new FileInputStream(imageFile);
        byte[] imageBytes = new byte[(int) imageFile.length()];
        imageInputStream.read(imageBytes);
        imageInputStream.close();

        return Base64.getEncoder().encodeToString(imageBytes);
    }

    private void decodeImageFromString(String base64EncodedImage, String outputPath) throws IOException {
        byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedImage);
        FileOutputStream imageOutputStream = new FileOutputStream(outputPath);
        imageOutputStream.write(decodedBytes);
        imageOutputStream.close();
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

    private boolean verifyHash(String message, String recievedHash) throws NoSuchAlgorithmException {
        String messageHash = calculateHash(message);
        if (messageHash.equals(recievedHash)) {
            return true;
        } else
            return false;
    }

    private String signWithPrivateKey(String message) {
        return message;

    }

    public static void main(String[] args) {
        // Security.addProvider(new BouncyCastleProvider());
        client = new Client(args[0]);
    }
}