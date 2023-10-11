import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;
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

public class Client {

  static Client client;
  SecretKey sessionKey;
  private GUI gui;
  PublicKey sendingClientPublicKey;

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
      System.exit(1);
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

          // Generate CSR
          PKCS10CertificationRequest csr = generateCSR(keyPair, username);

          // Convert CSR to String
          byte[] csrBytes = csr.getEncoded();
          String csrString = Base64.getEncoder().encodeToString(csrBytes);

          // Sign CSR with private key
          csrString = signWithPrivateKey(csrString); // the signWithPrivateKey method still needs to be implemented

          // Send CSR to CA
          outputStream.println(csrString);

          // Receive certificate from CA
          String certificateString = inputStream.readLine();
          System.out.println("Received certificate.");

          try {
            // Convert the certificate from String to X509Certificate
            byte[] certificateBytes = Base64.getDecoder().decode(certificateString);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(certificateBytes));
          } catch (Exception e) {
            e.printStackTrace();
          }

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

  private PKCS10CertificationRequest generateCSR(KeyPair keyPair, String username) {
    try {
      return new PKCS10CertificationRequest(
          "SHA256withRSA",
          new X500Principal("CN=" + username),
          keyPair.getPublic(),
          null,
          keyPair.getPrivate());

    } catch (Exception e) {
      e.printStackTrace();
      return null;
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
    } catch (Exception e) {
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
          String ivString = Base64.getEncoder().encodeToString(generatedIv);
          String ivStringHash = calculateHash(ivString);
          byte[] tagbytes = new byte[16];
          random.nextBytes(tagbytes);
          // authTag = tagbytes;
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

          if (verifyHash(sessionKeyString, sessionKeyHash)) {
            byte[] receivedSessionKeyBytes = Base64.getDecoder().decode(sessionKeyString);
            sessionKey = new SecretKeySpec(receivedSessionKeyBytes, "AES");
          } else {
            System.out.println("Session key recieved does not match message hash.");
            // resend message requesting session key
          }

        }
      }

      System.out.println("Session created.");

    } catch (Exception e) {
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
      gui = new GUI(this);
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
   * Message: <message>
   * Image: <image>
   * Image-Dimensions: <dimensions>
   * 
   * @param message The message to be sent
   * @param image   The image to be sent
   * @return The message protocol to be sent to the other client
   */
  private String messageGenerator(String message, ImageData image) {
    try {
      StringBuilder messageProtocol = new StringBuilder();
      messageProtocol.append("Message: ").append(message).append("\n");
      if (image != null) {
        messageProtocol.append("Image: ").append(image).append("\n");
        messageProtocol.append("Image-Dimensions: ").append(image.getWidth()).append(",").append(image.getHeight())
            .append("\n");
      }

      String temp = messageProtocol.toString();
      // hash message
      String messageHash = calculateHash(temp);
      String messageHashLine = "Message-Hash: " + messageHash + "\n";
      // create combination of message and hash
      messageProtocol.insert(0, messageHashLine);
      return messageProtocol.toString();
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return "";
    }
  }

  /**
   * This method is used to encrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be encrypted
   * @return The encrypted message protocol
   */
  private String encryptMessage(String message) {
    try {
      // Create a Cipher for Encryption
      Cipher cipher = Cipher.getInstance("AES");
      // use session key to encrypt it all
      cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
      byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
      // Encrypt the Message
      byte[] encryptedMessage = cipher.doFinal(messageBytes);
      return Base64.getEncoder().encodeToString(encryptedMessage);
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return "";
    }
  }

  /**
   * This method is used to decrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be decrypted
   * @return The decrypted message protocol
   */
  private String decryptMessage(String message) {
    try {
      // Create a Cipher for Decryption
      Cipher cipher = Cipher.getInstance("AES");
      cipher.init(Cipher.DECRYPT_MODE, sessionKey);

      // Assuming you have the encrypted message as a byte array
      byte[] encryptedMessage = Base64.getDecoder().decode(message.getBytes(StandardCharsets.UTF_8)); //
      // Replace with your encrypted message bytes
      byte[] decryptedMessageBytes = cipher.doFinal(encryptedMessage);
      //
      // Convert the decrypted byte array to a string
      String decryptedMessage = new String(decryptedMessageBytes,
          StandardCharsets.UTF_8);
      return decryptedMessage;
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return "";
    }
  }

  /**
   * This method is used to decrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be decrypted
   * @return The decrypted message protocol
   */
  private void sendMessageExecutor(String message, ImageData image) {
    try {
      PrintWriter outputStream = new PrintWriter(targetSocket.getOutputStream(), true);
      String messageToSend = messageGenerator(message, image);
      String encryptedMessage = encryptMessage(messageToSend);
      outputStream.println(encryptedMessage); // Send a message
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
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
  public void sendMessage(String message, ImageData image) {
    sendMessageExecutor(message, image);
  }

  private Map<String, String> parseMessage(List<String> messageLines) {
    Map<String, String> result = new HashMap<String, String>();

    for (String line : messageLines) {
      String[] lineSplit = line.split(":");
      String keyName = lineSplit[0].toLowerCase();

      if (keyName.equals("message-hash"))
        result.put("message-hash", lineSplit[1].trim());
      else if (keyName.equals("message"))
        result.put("message", lineSplit[1].trim());
      else if (keyName.equals("image"))
        result.put("image", lineSplit[1].trim());
      else if (keyName.equals("image-dimensions"))
        result.put("image-dimensions", lineSplit[1].trim());
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
      String decryptedMessage = decryptMessage(message);
      List<String> messageLines = Arrays.asList(decryptedMessage.split("\n"));
      String receivedHash = messageLines.get(0).split(":")[1].trim();
      String messageWithoutHash = String.join("\n", messageLines.subList(1, messageLines.size())) + "\n";

      if (verifyHash(messageWithoutHash, receivedHash)) {
        Map<String, String> parsedMessage = parseMessage(messageLines);
        if (parsedMessage.containsKey("message") && parsedMessage.containsKey("image")) {
          int imageWidth = Integer.parseInt(parsedMessage.get("image-dimensions").split(",")[0].trim());
          int imageHeight = Integer.parseInt(parsedMessage.get("image-dimensions").split(",")[1].trim());
          String encodedImage = parsedMessage.get("image");
          ImageData image = new ImageData(imageHeight, imageWidth, encodedImage);
          gui.setData(parsedMessage.get("message"), image);
        } else if (parsedMessage.containsKey("message")) {
          gui.setData(parsedMessage.get("message"), null);
        }

      }

    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      System.out.println("Unable to receive message. " + e.getMessage());
    }
  }

  /**
   * This method is used to calculate the hash of a message using SHA-256.
   *
   * @param message The message to be hashed
   * @return The hash of the message
   */
  private String calculateHash(String message) {
    try {
      // Get the private key for signing
      PrivateKey privateKey = keyPair.getPrivate();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hashBytes = md.digest(message.getBytes());
      // Initialize a Signature object with the private key
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privateKey);
      // Update the signature with the hash of the data
      signature.update(hashBytes);
      // Sign the data
      byte[] digitalSignature = signature.sign();
      return Base64.getEncoder().encodeToString(digitalSignature);
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return "";
    }
  }

  /**
   * This method is used to verify the hash of a message.
   *
   * @param message      The message to be checked
   * @param recievedHash The hash to be compared against
   * @return True if the hashes match, false otherwise
   */
  private boolean verifyHash(String message, String recievedHash) {
    try {
      // Create a hash of the data using SHA-256
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(message.getBytes());
      byte[] ditigalSignature = Base64.getDecoder().decode(recievedHash);
      Signature signature = Signature.getInstance("SHA256withRSA");
      // To verify the signature using the public key
      signature.initVerify(sendingClientPublicKey);
      signature.update(hash);
      return signature.verify(ditigalSignature);
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return false;
    }
  }

  private String signWithPrivateKey(String message) {
    return message;

  }

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());
    client = new Client(args[0]);
  }
}
