import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.List;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Client {

  private PublicKey publicKey;
  private PrivateKey privateKey;
  private SecretKey sessionKey;
  private X509Certificate certificate = null;
  private static Client clientInstance = null;

  public static void main(String[] args) {

    clientInstance = new Client();
    clientInstance.initializeClient();
  }

  public void startClient(Client client) {// used by the test class to pass an instance of this class to the methods
                                          // here
    System.out.println("Client started");
    clientInstance = client;
    clientInstance.initializeClient();
  }

  private void initializeClient() {
    clientInstance.genClientKeys();
    certificate = CA.signUp();
    if (certificate == null) {
      System.out.println("Error: Certificate is Null");
    } else {
      System.out.println("Certificate recieved");
      clientInstance.verifyCertificate(certificate);
    }

  }

  private void establishSession(boolean source) {
    // if source, creates a session, if not, completes the session the other client
    // initiated
    if (source) {// this client is beginning the session

      // send your public key
      // get their public key
      // apprach CA for their certificate
      // compare their certificate and public key

      clientInstance.genSessionKey();
      // encrypt session key using their pub key
      // encrypt session key using our private key
      // share session key using their public key

    } else {// this client is NOT beginning the session

      // return your public key
      // get public key of sender
      // get certificate of sender
      // compare public key and certificate
      // recieve the session key
      // decrypt session key using private key
      // decrpty session key using their public key
    }

  }

  private void genClientKeys() {// generate the public and private keys for this client

    try {
      // Generate a key pair using RSA
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);

      // Generate the key pair
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      // Retrieve the public and private keys from the key pair
      publicKey = keyPair.getPublic();
      privateKey = keyPair.getPrivate();
      System.out.println("Public and Private keys generated");

    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

  }

  private void genSessionKey() {
    try {
      // Create a KeyGenerator for AES
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      int keySize = 128;
      keyGen.init(keySize);
      // Generate the AES session key
      sessionKey = keyGen.generateKey();
      System.out.println("Session key generated");

    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  private boolean verifyCertificate(X509Certificate cert) {

    try {
      // Check if the certificate is not expired
      cert.checkValidity();

      System.out.println("The certificate is legit");
      return true;

    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
      System.out.println("The certificate is not legit");
      return false;
    }

  }

}

// get certificate from CA
// get public key from other user
// compare the two
