import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class Session {
  private Client client;
  private Socket targetSocket;
  public PublicKey otherClientPublicKey;
  private boolean active;
  public SecretKey sessionKey;
  private SecurityVault security;
  private X509Certificate certificate;
  private byte[] iv;

  public Session(Client client, Socket targetSocket, SecurityVault sv, Certificate cert) {
    this.client = client;
    this.targetSocket = targetSocket;
    security = sv;
    certificate = cert.certificate;
    createSession();
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
      inputStream = new BufferedReader(new InputStreamReader(targetSocket.getInputStream()));// get response from
                                                                                             // client

      if (client.username.equalsIgnoreCase("Alice")) {

        exchangeCertificates(outputStream, inputStream);

        // generate session key
        // System.out.println("Generating session key.");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        sessionKey = keyGenerator.generateKey();
        security.updateSessionKey(sessionKey);

        byte[] sessionKeyBytes = sessionKey.getEncoded();
        String sessionKeyString = new String(sessionKeyBytes);
        String sessionKeyHash = security.calculateHash(sessionKeyString); // calculate hash

        // Generate a random IV
        // System.out.println("Generating Initialisation vector for session");
        SecureRandom secureRandom = new SecureRandom();
        byte[] generatedIV = new byte[16]; // 16 bytes for AES
        secureRandom.nextBytes(generatedIV);
        iv = generatedIV;
        byte[] ivHash = security.calculateHash(iv);

        // encrypt the session key
        // System.out.println("Encrypting session key and initialisation vector.");
        byte[] encryptedIV = security.encryptRSA(iv);
        byte[] encryptedSessionKey = security.encryptRSA(sessionKeyBytes);
        // String encryptedSessionKeyString = new String(encryptedSessionKey);

        // encode message
        // System.out.println("Encoding session key and initialisation vector to
        // strings.");
        String encodedSessionKeyHash = Base64.getEncoder().encodeToString(sessionKeyHash.getBytes());
        String encodedEncryptedSessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
        String encodedMessage = encodedSessionKeyHash + "/r/n" + encodedEncryptedSessionKey;

        String encodedIVHash = Base64.getEncoder().encodeToString(ivHash);
        String encodedEncryptedIV = Base64.getEncoder().encodeToString(encryptedIV);
        String encodedMessageIV = encodedIVHash + "/r/n" + encodedEncryptedIV;

        // System.out.println("Transmitting session key and initialisation vector to
        // Bob.");
        outputStream.println(encodedMessage); // send message
        outputStream.println(encodedMessageIV);

      } else if (client.username.equalsIgnoreCase("Bob")) {
        exchangeCertificates(outputStream, inputStream);

        // get session key from other client
        String message = inputStream.readLine();
        String messageIV = inputStream.readLine();
        // System.out.println("Received session key and initialisation vector from
        // Alice.");
        String[] data = message.split("/r/n");
        String[] dataIV = messageIV.split("/r/n");
        String encodedSessionKeyHash = data[0];
        String encodedEncryptedSessionKey = data[1];
        String encodedIVHash = dataIV[0];
        String encodedIV = dataIV[1];
        byte[] sessionKeyHash = Base64.getDecoder().decode(encodedSessionKeyHash.getBytes());
        String sessionKeyHashString = new String(sessionKeyHash);
        byte[] encryptedSessionKey = Base64.getDecoder().decode(encodedEncryptedSessionKey.getBytes());
        byte[] ivHash = Base64.getDecoder().decode(encodedIVHash.getBytes());
        byte[] encryptedIV = Base64.getDecoder().decode(encodedIV.getBytes());
        // System.out.println("Decrypting session key and initialisation vector.");
        byte[] ivBytes = security.decryptRSA(encryptedIV);
        byte[] sessionKeyBytes = security.decryptRSA(encryptedSessionKey);
        String sessionKeyString = new String(sessionKeyBytes);

        // System.out.println("Verifying hash codes of session key and initialisation
        // vector.");
        if (security.verifyHash(sessionKeyString, sessionKeyHashString) && security.verifyHash(ivBytes, ivHash)) {
          // System.out
          // .println("Session key and initialisation vector verified and have not been
          // tampered durng transmission.");
          sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
          security.updateSessionKey(sessionKey);
          iv = ivBytes;
        } else {
          System.out.println("Error, session key does not match its hash.");
        }

      }

      System.out.println("Session created.");

    } catch (Exception e) {
      System.out.println("Error in create session catch");
      // if (client.username.equalsIgnoreCase("Alice"))
      // System.out.println("Bob's certificate is invalid.");
      // else
      // System.out.println("Alice's certificate is invalid.");
      e.printStackTrace(outputStream);
    }
  }

  public byte[] getIV() {
    return iv;
  }

  private void exchangeCertificates(PrintWriter outputStream, BufferedReader inputStream)
      throws IOException, CertificateException {
    if (client.username.equalsIgnoreCase("Alice")) {
      // send this clients certificate certificate
      // System.out.println("Sending certificate to Bob.");
      byte[] certificateBytes = certificate.getEncoded();
      String certificateString = Base64.getEncoder().encodeToString(certificateBytes);
      outputStream.println(certificateString);

      // get other clients certificate and extract public key
      String otherCertString = inputStream.readLine();
      // System.out.println("Receiving Bob's Certificate.");
      byte[] otherCertBytes = Base64.getDecoder().decode(otherCertString);
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      X509Certificate other_Client_certificate = (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(otherCertBytes));
      // System.out.println("Verifying Bob's Certificate.");
      other_Client_certificate.checkValidity();
      // System.out.println("Bob's certificate is valid.");

      otherClientPublicKey = other_Client_certificate.getPublicKey();
      security.updateTargetPublicKey(otherClientPublicKey);

    } else if (client.username.equalsIgnoreCase("Bob")) {
      // get other clients certificate and extract public key
      // System.out.println("Receiving Alice's Certificate.");
      String otherCertString = inputStream.readLine();
      byte[] otherCertBytes = Base64.getDecoder().decode(otherCertString);
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      X509Certificate other_Client_certificate = (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(otherCertBytes));
      // System.out.println("Verifying Alice's Certificate.");
      other_Client_certificate.checkValidity();
      // System.out.println("Alice's certificate is valid.");

      otherClientPublicKey = other_Client_certificate.getPublicKey();
      security.updateTargetPublicKey(otherClientPublicKey);

      // send this clients certificate certificate
      // System.out.println("Sending certificate to Alice.");
      byte[] certificateBytes = certificate.getEncoded();
      String certificateString = Base64.getEncoder().encodeToString(certificateBytes);
      outputStream.println(certificateString);

    }

    System.out.println("Certificates exchanged and verified.");
  }

  // Shuffle the bytes within the certificate to make it invalid
  private static byte[] alterCertificate(byte[] certificateBytes) {
    // Create a random number generator
    Random random = new Random();

    // Shuffle the bytes by swapping pairs of bytes randomly
    for (int i = 0; i < certificateBytes.length; i += 2) {
      int j = random.nextInt(certificateBytes.length);
      byte temp = certificateBytes[i];
      certificateBytes[i] = certificateBytes[j];
      certificateBytes[j] = temp;
    }

    return certificateBytes;
  }

  public boolean isActive() {
    return active;
  }

  public void endSession() {
    active = false;
  }

}
