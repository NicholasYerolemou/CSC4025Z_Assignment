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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
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
import java.util.Random;
import java.util.List;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import java.security.SecureRandom;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Client {

  static Client client;
  private GUI gui;
  private SecurityVault security;
  private Session session;
  private Certificate certificate;
  Thread userListenerThread;

  private static boolean connected = false;
  private Socket targetSocket = null;// the socket if the client you are connected to
  public String username;

  public Client(String name) {
    username = name;
    if (name.equalsIgnoreCase("Alice")) {
      security = new SecurityVault();
      certificate = new Certificate(security, username);
      connectAsServer();
    } else if (name.equalsIgnoreCase("Bob")) {
      security = new SecurityVault();
      certificate = new Certificate(security, username);
      connectAsClient();
    } else {
      System.out.println("Not a valid username. Enter either Alice or Bob");
      System.exit(1);
    }
  }

  public String getName() {
    return username;
  }

  private void connectAsServer() {
    // initializes connection and waits for bob to connect
    int PORT = 12345;
    try {
      ServerSocket serverSocket = new ServerSocket(PORT);
      // the socket this client is listening for connections on
      // System.out.println("Listening on port " + PORT);

      // Accept incoming client connections
      targetSocket = serverSocket.accept();
      // the socket of the client we are connected to
      // System.out.println("Client connected from " +
      // targetSocket.getInetAddress().getHostAddress() + ".");
      connected = true;
      session = new Session(this, targetSocket, security, certificate);
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
      // System.out.println("Connected to client at " + SERVER_ADDRESS + ":" + PORT);
      connected = true;
      session = new Session(this, targetSocket, security, certificate);
      listenForUserInput();
      listenForMessages();

      // socket.close();
    } catch (Exception e) {
      System.err.println("Error connecting to other client: " + e.getMessage());
    }
  }

  private void listenForUserInput() {
    // Create another thread to listen for user input to trigger sending a message.

    userListenerThread = new Thread(() -> {
      // System.out.println("Listening for user input.");
      gui = new GUI(this);

    });
    userListenerThread.start();

  }

  private void listenForMessages() {
    // System.out.println("Listening for incoming messages.");

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
          System.out.println("Closing connection to client");
          gui.close();
        } else {
          recieveMessage(receivedMessage);
        }

      } catch (IOException e) {
        e.printStackTrace();
      }

    }

  }

  /**
   * This method is used to generate the message protocol that will be sent to the
   * other client.
   *
   * Message structure below(newline delimiter):
   * Message-Hash::> <hash of message>
   * Message::> <message>
   * Image::> <image>
   * Image-Dimensions::> <dimensions>
   * 
   * @param message The message to be sent
   * @param image   The image to be sent
   * @return The message protocol to be sent to the other client
   */
  private String messageGenerator(String message, ImageData image) {
    try {
      StringBuilder messageProtocol = new StringBuilder();
      messageProtocol.append("Message::> ").append(message).append("\n");
      if (image != null) {
        messageProtocol.append("Image::> ").append(image.encodeImage()).append("\n");
        messageProtocol.append("Image-Dimensions::> ").append(image.getWidth()).append(",").append(image.getHeight())
            .append("\n");
      }

      String temp = messageProtocol.toString();
      // hash message
      String messageHash = security.calculateHash(temp);
      String messageHashLine = "Message-Hash::> " + messageHash + "\n";
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
   * This method is used to decrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be decrypted
   * @return The decrypted message protocol
   */
  private void sendMessageExecutor(String message, ImageData image) {
    try {
      PrintWriter outputStream = new PrintWriter(targetSocket.getOutputStream(), true);
      String messageToSend = messageGenerator(message, image);
      String encryptedMessage = security.encryptMessage(messageToSend, session.getIV());
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
      String[] lineSplit = line.split("::>");
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
      String decryptedMessage = security.decryptMessage(message, session.getIV());
      List<String> messageLines = Arrays.asList(decryptedMessage.split("\n"));
      String receivedHash = messageLines.get(0).split("::>")[1].trim();
      String messageWithoutHash = String.join("\n", messageLines.subList(1, messageLines.size())) + "\n"; // New line

      if (security.verifyHash(messageWithoutHash, receivedHash)) {
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

  // Shuffle the bytes within the certificate to make it invalid
  private static byte[] alterCertificate(byte[] certificateBytes) {
    // Create a random number generator
    Random random = new Random();
    int max = 256;
    if (certificateBytes.length < max)
      max = certificateBytes.length;

    // Shuffle the bytes by swapping pairs of bytes randomly
    for (int i = 0; i < max; i += 1) {
      int j = random.nextInt(max);
      byte temp = certificateBytes[i];
      certificateBytes[i] = certificateBytes[j];
      certificateBytes[j] = temp;
    }

    return certificateBytes;
  }

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());
    client = new Client(args[0]);
  }
}
