import java.awt.RenderingHints.Key;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SecurityVault {

  private KeyPair keyPair;
  private SecretKey sessionKey;
  private PublicKey otherClientPublicKey;
  // private byte[] iv;

  public SecurityVault() {
    // this.iv = initV;
    generateKeys();

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

  /**
   * This method is used to encrypt the message protocol using AES encryption.
   *
   * @param message The message protocol to be encrypted
   * @return The encrypted message protocol
   */
  public String encryptMessage(String message, byte[] iv) {
    try {
      // Create a Cipher for Encryption
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      // use session key to encrypt it all
      cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
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
  public String decryptMessage(String message, byte[] iv) {
    try {
      // Create a Cipher for Decryption
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));

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

  public byte[] encryptRSA(byte[] messageBytes) {

    try {

      // encrypt with their public key
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, otherClientPublicKey);
      byte[] encryptedBytes = cipher.doFinal(messageBytes);

      // encrypt with our private key
      // cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
      // encryptedBytes = cipher.doFinal(encryptedBytes);

      return encryptedBytes;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
        | BadPaddingException e) {
      e.printStackTrace();
      return null;
    }
  }

  public byte[] decryptRSA(byte[] messageBytes) {

    try {

      byte[] decryptedBytes = messageBytes;
      Cipher cipher;

      // decrypt with their public key
      // cipher.init(Cipher.DECRYPT_MODE, otherClientPublicKey);
      // decryptedBytes = cipher.doFinal(decryptedBytes);

      // decrypt our private key
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
      decryptedBytes = cipher.doFinal(decryptedBytes);

      return decryptedBytes;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
        | InvalidKeyException e) {

      e.printStackTrace();
      System.out.println("Error thrown in decrypt RSA");
      return null;
    }

  }

  /**
   * This method is used to calculate the hash of a message using SHA-256.
   *
   * @param message The message to be hashed
   * @return The hash of the message
   */
  public String calculateHash(String message) {
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
   * This method is used to calculate the hash of a message using SHA-256.
   *
   * @param message The message to be hashed
   * @return The hash of the message
   */
  public byte[] calculateHash(byte[] message) {
    try {
      // Get the private key for signing
      PrivateKey privateKey = keyPair.getPrivate();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hashBytes = md.digest(message);
      // Initialize a Signature object with the private key
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privateKey);
      // Update the signature with the hash of the data
      signature.update(hashBytes);
      // Sign the data
      byte[] digitalSignature = signature.sign();
      return digitalSignature;
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return null;
    }
  }

  /**
   * This method is used to verify the hash of a message.
   *
   * @param message      The message to be checked
   * @param recievedHash The hash to be compared against
   * @return True if the hashes match, false otherwise
   */
  public boolean verifyHash(String message, String recievedHash) {
    try {
      // Create a hash of the data using SHA-256
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(message.getBytes());
      byte[] ditigalSignature = Base64.getDecoder().decode(recievedHash);
      Signature signature = Signature.getInstance("SHA256withRSA");
      // To verify the signature using the public key
      signature.initVerify(otherClientPublicKey);
      signature.update(hash);
      return signature.verify(ditigalSignature);
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return false;
    }
  }

  /**
   * This method is used to verify the hash of a message.
   *
   * @param message      The message to be checked
   * @param recievedHash The hash to be compared against
   * @return True if the hashes match, false otherwise
   */
  public boolean verifyHash(byte[] message, byte[] ditigalSignature) {
    try {
      // Create a hash of the data using SHA-256
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(message);
      // byte[] ditigalSignature = Base64.getDecoder().decode(recievedHash);
      Signature signature = Signature.getInstance("SHA256withRSA");
      // To verify the signature using the public key
      signature.initVerify(otherClientPublicKey);
      signature.update(hash);
      return signature.verify(ditigalSignature);
    } catch (Exception e) {
      // TODO: handle exception
      e.printStackTrace();
      return false;
    }
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }

  public void updateSessionKey(SecretKey sk) {
    sessionKey = sk;
  }

  public void updateTargetPublicKey(PublicKey otherClientPublicKey) {
    this.otherClientPublicKey = otherClientPublicKey;
  }
}
