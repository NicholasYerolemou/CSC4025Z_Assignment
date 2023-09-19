import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class client {

  private PublicKey publicKey;
  private PrivateKey privateKey;

  public static void main(String[] args) {

    client clientInstance = new client();
    clientInstance.initializeConnection();

  }

  private boolean initializeConnection() {// Initializes client for communication
    // Returns True is connection suceeded, false otherwise

    genClientKeys();
    getCertificate();
    exchangeCertificate();
    genSessionKey();
    genSessionKey();

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

  private void getCertificate() {// call the sign up method from the CA class and recieve a certificate
  }

  private void exchangeCertificate() {
  }

  private void genSessionKey() {
  }

}
