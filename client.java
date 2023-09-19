import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class client {

  private PublicKey publicKey;
  private PrivateKey privateKey;
  private SecretKey sessionKey;
  private X509Certificate certificate = null;

  public static void main(String[] args) {

    client clientInstance = new client();
    clientInstance.initializeConnection();

  }

  private boolean initializeConnection() {// Initializes client for communication
    // Returns True is connection suceeded, false otherwise

    genClientKeys();
    certificate = CA.signUp();
    if (certificate == null) {

    }
    exchangeCertificate();

    try {
      sessionKey = genSessionKey();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    return false;
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

    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

  }

  private void exchangeCertificate() {
  }

  private SecretKey genSessionKey() throws NoSuchAlgorithmException {
    try {
      // Create a KeyGenerator for AES
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      int keySize = 128;
      keyGen.init(keySize);
      // Generate the AES session key
      SecretKey sessionKey = keyGen.generateKey();

      // Return the generated session key
      return sessionKey;
    } catch (NoSuchAlgorithmException e) {
      throw e;
    }
  }

}