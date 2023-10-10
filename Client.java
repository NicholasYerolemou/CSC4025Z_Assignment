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
import javax.crypto.IllegalBlockSizeException;
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
import javax.crypto.spec.IvParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import java.security.SecureRandom;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class Client {

  static Client client;
  SecretKey sessionKey;
  private PublicKey publicKey;
  private PrivateKey privateKey;

  private KeyPair keyPair;
  private static boolean connected = false;
  private Socket targetSocket = null;// the socket if the client you are connected to
  private String username;
  private byte[] iv;
  private byte[] authTag;

  public Client(String name) {
    // Security.addProvider(new BouncyCastleProvider());

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
          // IvParameterSpec generatedIv = new IvParameterSpec(ivBytes);
          SecureRandom random = new SecureRandom();
          byte[] generatedIv = new byte[16];
          random.nextBytes(generatedIv);
          iv = generatedIv;
          String ivString = Base64.getEncoder().encodeToString(generatedIv);
          String ivStringHash = calculateHash(ivString);
          byte[] tagbytes = new byte[16];
          random.nextBytes(tagbytes);
          authTag = tagbytes;
          String tagBytesString = Base64.getEncoder().encodeToString(tagbytes);
          String tagBytesStringHash = calculateHash(tagBytesString);

          // send message
          String message = sessionKeyString + "," + sessionKeyhashString + "," + ivString + "," + ivStringHash + ","
              + tagBytesString + "," + tagBytesStringHash;
          outputStream.println(message);

        } else if (username.equalsIgnoreCase("Bob")) {
          // Simulate receiving the session key and its hash from Alice

          System.out.println("Waiting for session key.");
          String message = inputStream.readLine();
          String[] data = message.split(",");
          String sessionKeyString = data[0];
          String sessionKeyHash = data[1];
          String ivString = data[2];
          String ivStringHash = data[3];
          System.out.println("Session key has been retrieved");
          System.out.println("IV has been received");

          if (verifyHash(sessionKeyString, sessionKeyHash) && verifyHash(ivString, ivStringHash)) {
            System.out.println("Session key has been verified");
            System.out.println("IV has been verified");

            byte[] receivedSessionKeyBytes = Base64.getDecoder().decode(sessionKeyString);
            sessionKey = new SecretKeySpec(receivedSessionKeyBytes, "AES");

            byte[] ivDecoded = Base64.getDecoder().decode(ivString);
            iv = ivDecoded;
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

      // out = new PrintWriter(targetSocket.getOutputStream(), true);
      // } catch (IOException e) {
      // System.out.println("Failed to create writer to client" + e.getMessage());
      // }

      // while (connected) {
      // // listen for user input
      // Scanner scanner = new Scanner(System.in);
      // String userInput = scanner.nextLine();
      // sendMessage(userInput, out);

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

  /**
   * This method is used to generate the message protocol that will be sent to the
   * other client.
   *
   * Message structure below(newline delimiter):
   * Message-Hash: <hash of message>
   * Certificate: <certificate of sender>
   * Message: <message>
   * Image: <image>
   * 
   * @param certificate The certificate of the client sending the message
   * @param message     The message to be sent
   * @param image       The image to be sent
   * @return The message protocol to be sent to the other client
   */
  private String messageGenerator(String certificate, String message, String image) throws NoSuchAlgorithmException {
    StringBuilder messageProtocol = new StringBuilder();
    messageProtocol.append("Certificate: ").append(certificate).append("\n");
    messageProtocol.append("Message: ").append(message).append("\n");
    if (image != null)
      messageProtocol.append("Image: ").append(image).append("\n");
    String temp = messageProtocol.toString();
    // hash message
    String messageHash = calculateHash(temp);
    String messageHashLine = "Message-Hash: " + messageHash + "\n";
    // create combination of message and hash
    messageProtocol.insert(0, messageHashLine);
    return messageProtocol.toString();
  }

  /**
   * This method is used to encrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be encrypted
   * @return The encrypted message protocol
   */
  private String encryptMessage(String message) throws Exception {
    System.out.println("encrypting IV: " + Arrays.toString(iv));
    // Create a Cipher for Encryption
    Cipher cipher = Cipher.getInstance("AES");
    // use session key to encrypt it all
    cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
    byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
    System.out.println("Encryption message size:" + messageBytes.length);
    System.out.println("Encryption message modulo:" + messageBytes.length % 16);
    // Encrypt the Message
    byte[] encryptedMessage = cipher.doFinal(messageBytes);
    return Base64.getEncoder().encodeToString(encryptedMessage);
  }

  /**
   * This method is used to decrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be decrypted
   * @return The decrypted message protocol
   */
  private String decryptMessage(String message) throws Exception {
    System.out.println("decrypting IV: " + Arrays.toString(iv) + "\nLenghth:" +
        iv.length);
    // Create a Cipher for Decryption
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));

    // Assuming you have the encrypted message as a byte array
    byte[] encryptedMessage = Base64.getDecoder().decode(message.getBytes(StandardCharsets.UTF_8)); //
    // Replace with your encrypted message bytes
    System.out.println("Decrypting message size:" + encryptedMessage.length);
    System.out.println("Decrypting message modulo:" + encryptedMessage.length %
        16);
    byte[] decryptedMessageBytes = cipher.doFinal(encryptedMessage);
    //
    // Convert the decrypted byte array to a string
    String decryptedMessage = new String(decryptedMessageBytes,
        StandardCharsets.UTF_8);
    return decryptedMessage;
  }

  /**
   * This method is used to decrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be decrypted
   * @return The decrypted message protocol
   */
  private void sendMessageExecutor(String message, String image) {
    try {
      PrintWriter outputStream = new PrintWriter(targetSocket.getOutputStream(), true);
      // System.out.println("Message sent: " + message + ".");
      // TODO: Place the actual certificate here
      String messageToSend = messageGenerator("certificate", message, image);
      String encryptedMessage = encryptMessage(messageToSend);
      outputStream.println(encryptedMessage); // Send a message
      System.out.println("Message has been sent");
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
      System.out.println("Unable to send message. " + e.getMessage());
    }
  }

  /**
   * This method is used to send a message to the other client.
   *
   * @param message The message to be sent
   */
  public void sendMessage(String message) {
    sendMessageExecutor(message, null);
  }

  /**
   * This method is used to send a message and an image to the other client.
   *
   * @param message The message to be sent
   * @param image   The image to be sent
   */
  public void sendMessage(String message, String image) {
    sendMessageExecutor(message, image);
  }

  private Map<String, String> parseMessage(List<String> messageLines) {
    Map<String, String> result = new HashMap<String, String>();

    for (String line : messageLines) {
      String[] lineSplit = line.split(":");
      String keyName = lineSplit[0].toLowerCase();

      if (keyName.equals("message-hash"))
        result.put("message-hash", lineSplit[1].trim());
      else if (keyName.equals("certificate"))
        result.put("certificate", lineSplit[1].trim());
      else if (keyName.equals("message"))
        result.put("message", lineSplit[1].trim());
      else if (keyName.equals("image"))
        result.put("image", lineSplit[1].trim());
    }

    return result;
  }

  /**
   * This method is used to process an incoming message.
   *
   * @param message The message to be processed transmitted by the sending client
   */
  private void recieveMessage(String message) {
    try {
      System.out.println("Received message: " + message);
      String decryptedMessage = decryptMessage(message);
      List<String> messageLines = Arrays.asList(decryptedMessage.split("\n"));
      String receivedHash = messageLines.get(0).split(":")[1].trim();
      String messageWithoutHash = String.join("\n", messageLines.subList(1, messageLines.size())) + "\n";

      if (verifyHash(messageWithoutHash, receivedHash)) {
        Map<String, String> parsedMessage = parseMessage(messageLines);
        for (Map.Entry<String, String> entry : parsedMessage.entrySet()) {
          System.out.println(entry.getKey() + ": " + entry.getValue());
        }

      }

    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      System.out.println("Unable to receive message. " + e.getMessage());
    }
    // Process the incoming message here
    // use session key to decrypt the message
    // Remove hash from message
    // compue hash on message without hash compare with hash
    // decode the message
    // display/print out the message
    // System.out.println("Message Recieved: " + message);
  }

  /**
   * This method is used to send an image to the other client.
   *
   * @param image The image to be sent
   */
  private String encodeImageToString(byte[] imageBytes) throws IOException {
    return Base64.getEncoder().encodeToString(imageBytes);
  }

  /**
   * This method is used to decode an image from a Base64 string.
   *
   * @param base64EncodedImage The Base64 string to be decoded
   * @param outputPath         The path to save the decoded image
   */
  private void decodeImageFromString(String base64EncodedImage, String outputPath) throws IOException {
    byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedImage);
    FileOutputStream imageOutputStream = new FileOutputStream(outputPath);
    imageOutputStream.write(decodedBytes);
    imageOutputStream.close();
  }

  /**
   * This method is used to calculate the hash of a message using SHA-256.
   *
   * @param message The message to be hashed
   * @return The hash of the message
   */
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

  /**
   * This method is used to verify the hash of a message.
   *
   * @param message      The message to be checked
   * @param recievedHash The hash to be compared against
   * @return True if the hashes match, false otherwise
   */
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
    Security.addProvider(new BouncyCastleProvider());
    // client = new Client(args[0]);
    client = new Client("Bob");
  }
}
