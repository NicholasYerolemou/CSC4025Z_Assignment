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






public class Client {
    
SecretKey sessionKey;
private PublicKey publicKey;
private PrivateKey privateKey;
private static boolean connected = false;
private Socket targetSocket = null;//the socket if the client you are connected to 
private String username;

public Client(String name)
{
   
    username = name;
    if(name.equalsIgnoreCase("Alice"))
    {   
        generateKeys();
        getCertificate();
        connectAsServer(); 
    }
    else if(name.equalsIgnoreCase("Bob"))
    {
        generateKeys();
        getCertificate();
        connectAsClient();
    }
    else
    {
        System.out.println("Not a valid username. Enter either Alice or Bob");
    }
        

}

private void generateKeys()
{
    //generate this clients pub and private keys
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

private void getCertificate()
{
    //connect to the CA and request a new certificate
    Socket CA_Socket = connectToCA();
    // if(CA_Socket!=null)
    // {
    //     System.out.println("Connected to CA.");
    //     //request new certificate
    //     //we may need to first establish a secure channel
    //     try (PrintWriter outputStream = new PrintWriter(CA_Socket.getOutputStream(), true)) {
    //         outputStream.println("0");//0 indicates we want a new certificate
    //         //CA sends back their public key
    //         InputStream inputStream = CA_Socket.getInputStream();
    //         DataInputStream dataInputStream = new DataInputStream(inputStream);
    //         int keyLength = dataInputStream.readInt();
    //         byte[] receivedPublicKeyBytes = new byte[keyLength];
    //         dataInputStream.readFully(receivedPublicKeyBytes);
    //         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    //         X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(receivedPublicKeyBytes);
    //         PublicKey CA_PublicKey = keyFactory.generatePublic(publicKeySpec);


    //         //we send the info needed to create a certificate
    //         Signature signature = Signature.getInstance("SHA256withRSA");
    //         signature.initSign(privateKey);

    //         byte[] publicKeyBytes = publicKey.getEncoded();
    //         String commonName = username;
    //         byte[] commonNameBytes = commonName.getBytes();

    //         //create a message with both byte arrays
    //         int length1 = publicKeyBytes.length;
    //         int length2 = commonNameBytes.length;
    //         byte[] certificateRequestInfo = new byte[length1 + length2];
    //         System.arraycopy(publicKeyBytes, 0, certificateRequestInfo, 0, length1);
    //         System.arraycopy(commonName, 0, certificateRequestInfo, length1, length2);
    //         //enctrypt the message with out private key
    //         signature.update(certificateRequestInfo);
    //         byte[] encryptedMessage = signature.sign();

    //         //send the message to the CA
    //         DataOutputStream dataOutputStream = new DataOutputStream(CA_Socket.getOutputStream());
    //         dataOutputStream.writeInt(encryptedMessage.length);
    //         dataOutputStream.write(encryptedMessage);
    //         dataOutputStream.flush();

            

    //     } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
           
    //         e.printStackTrace();
    //         //can potentially restart the method here and attempt it again
    //     }
    // }
    // else
    // {
    //     System.out.println("Unable to connect to CA.");
        
    // }

    

    
}

private Socket connectToCA()
{
    int CA_PORT = 12346;// CA's port number
    String CA_ADDRESS = "127.0.0.1";
    Socket CA_Socket = null;
    try {
        CA_Socket = new Socket(CA_ADDRESS, CA_PORT);
    } catch (IOException e) {
        System.out.println("Unable to connect to CA. Attempting again in 5 seconds.");
        //this doesnt work properly yet
        try {
            Thread.sleep(5000);
            connectToCA();
        } catch (InterruptedException e1) {
            e1.printStackTrace();
        }
    }
    return CA_Socket;

}

private void connectAsServer()
{
    // initializes connection and waits for bob to connect
    int PORT = 12345;
    try {
    ServerSocket serverSocket = new ServerSocket(PORT);
    //the socket this client is listening for connections on 
    System.out.println("Listening on port " + PORT);

    // Accept incoming client connections
        targetSocket = serverSocket.accept();
        //the socket of the client we are connected to
        System.out.println("Client connected from " + targetSocket.getInetAddress().getHostAddress()+".");
        connected = true;
        createSession();
        listenForUserInput();
        listenForMessages();

    } catch (IOException e) {
        e.printStackTrace();
    }
}


private void connectAsClient()
{
    int PORT = 12345;
    String SERVER_ADDRESS = "127.0.0.1"; // Change this to Alice's server address if needed

    try {
        
        targetSocket = new Socket(SERVER_ADDRESS, PORT);
        //the socket of the client we are connected to 
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

private void createSession()
{   
    //called after a connection is established
    //exchange certificates and generate session key
    //then begin listening

    System.out.println("Creating session.");
    PrintWriter outputStream = null;
    BufferedReader inputStream = null;
    String response;
    try{
        
        outputStream = new PrintWriter(targetSocket.getOutputStream(), true);
        outputStream.println("Your certificate goes here");//send your certificate here 
        inputStream = new BufferedReader(new InputStreamReader(targetSocket.getInputStream()));//get response from client
        response = inputStream.readLine();
        boolean verified = verifyCertificate(response);
        verified = true;
        //The response should contain their certificate
        
        if(verified)
        {
            
            

            if (username.equalsIgnoreCase("Alice")) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(128); // Change to the desired key size
                sessionKey = keyGenerator.generateKey();
                String sessionKeyBase64 = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] sessionKeyHash = sha256.digest(sessionKey.getEncoded());
                String sessionKeyHashBase64 = Base64.getEncoder().encodeToString(sessionKeyHash);

                outputStream.println(sessionKeyBase64);
                outputStream.println(sessionKeyHashBase64);

                // Simulate sending the session key and its hash to Bob
                System.out.println("Alice - Session Key: " + sessionKeyBase64);
                System.out.println("Alice - Session Key Hash: " + Base64.getEncoder().encodeToString(sessionKeyHash));

            } else if (username.equalsIgnoreCase("Bob")) {
                // Simulate receiving the session key and its hash from Alice
                
                String receivedSessionKeyBase64 = inputStream.readLine(); // Replace with the received session key string
                String receivedSessionKeyHashBase64 = inputStream.readLine(); // Replace with the received session key hash string

                byte[] receivedSessionKeyBytes = Base64.getDecoder().decode(receivedSessionKeyBase64);
                byte[] receivedSessionKeyHash = Base64.getDecoder().decode(receivedSessionKeyHashBase64);
                // Calculate the hash of the received session key
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] calculatedSessionKeyHash = sha256.digest(receivedSessionKeyBytes);
                // Compare the calculated hash to the received hash
                boolean keysMatch = MessageDigest.isEqual(receivedSessionKeyHash, calculatedSessionKeyHash);

                // Visual inspection
                System.out.println("Bob - Received Session Key: " + Base64.getEncoder().encodeToString(receivedSessionKeyBytes));
                System.out.println("Bob - Calculated Session Key Hash: " + Base64.getEncoder().encodeToString(calculatedSessionKeyHash));

                if (keysMatch) {
                    System.out.println("Session keys match.");
                    sessionKey =  new SecretKeySpec(receivedSessionKeyBytes, "AES");
                } else {
                    System.out.println("Session keys do not match. Possible tampering.");
                }
            }

            
            //encode session key with our private key
            //ecnode session key with their public key
            //send session key
            //store session key locally
        } 

    }
    catch (IOException | NoSuchAlgorithmException e)
    {
        System.out.println("Failed to create writer to client"+e.getMessage());
    }
}


private boolean verifyCertificate(String recievedCertificate)
{
    return true;//return true if the certificate is verified, false otherwise
    //store their public key on our system
    //To verify - check if it can be decrypted by the CA's public key
}

private void listenForUserInput()
{
    //Create another thread to listen for user input to trigger sending a message.

    

    Thread userListenerThread = new Thread(() -> {
    System.out.println("Listening for user input.");
    // Create output stream
    PrintWriter out = null;
    
    try{
        
        out = new PrintWriter(targetSocket.getOutputStream(), true);
    }
    catch (IOException e)
    {
        System.out.println("Failed to create writer to client"+e.getMessage());
    }

    while(connected)
    {
        //listen for user input
        Scanner scanner = new Scanner(System.in);
        String userInput = scanner.nextLine();
        sendMessage(userInput, out);
        
    }
    });
    userListenerThread.start();

}


private void listenForMessages()
{
        System.out.println("Listening for incoming messages.");


        //listen for a recieved input to trigger processing a message.

        // Create input and output streams
        BufferedReader in = null;
    
        try{
            in = new BufferedReader(new InputStreamReader(targetSocket.getInputStream()));
        }
        catch (IOException e)
        {
            System.out.println("Failed to create reader to client"+e.getMessage());
        }

        while(connected)
        {
            
            // Receive messages
            String receivedMessage;
            try {
                receivedMessage = in.readLine();
                
                if (receivedMessage == null)
                {
                    //the other client has disconnected
                    connected = false;
                    System.out.println("Connected set to: "+connected);
                }
                else
                {
                    recieveMessage(receivedMessage);
                }
                
            } catch (IOException e) {
                System.out.print("error");
                e.printStackTrace();
            }

           
        }
      
}

private void sendMessage(String message, PrintWriter outWriter)
{
    //process the outgoing message here

    //encode message (message is the image) to a string
    //hash message
    //create combination of message and hash
    //use session key to encrypt it all
    //send it to the client
    System.out.println("Message sent: "+message+".");
        outWriter.println(message); // Send a message
}
private void recieveMessage(String message)
{
    //Process the incoming message here
    //use session key to decrypt the message
    //Remove hash from message
    //compue hash on message without hash compare with hash
    //decode the message
    //display/print out the message
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


public static void main (String [] args)
{
    // Security.addProvider(new BouncyCastleProvider());
    Client client = new Client(args[0]);
}
}



