import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

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

    
      

    public Session(Client client,Socket targetSocket,SecurityVault sv,Certificate cert)
    {
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
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        sessionKey = keyGenerator.generateKey();
        security.updateSessionKey(sessionKey);

        byte[] encryptedMessage = sessionKey.getEncoded();
        encryptedMessage = security.encryptRSA(encryptedMessage);

        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        outputStream.println(encodedMessage); // send message

      } else if (client.username.equalsIgnoreCase("Bob")) {
        exchangeCertificates(outputStream, inputStream);

        // get session key from other client
        String message = inputStream.readLine();
        byte[] decodedMessage = Base64.getDecoder().decode(message);

        decodedMessage = security.decryptRSA(decodedMessage);
        sessionKey = new SecretKeySpec(decodedMessage, "AES");
        security.updateSessionKey(sessionKey);
      }

      System.out.println("Session created.");

    } catch (Exception e) {
      System.out.println("Error in create session catch");
      e.printStackTrace(outputStream);
    }
  }
    
  private void exchangeCertificates(PrintWriter outputStream, BufferedReader inputStream)
      throws IOException, CertificateException {
    if (client.username.equalsIgnoreCase("Alice")) {
      // send this clients certificate certificate
      byte[] certificateBytes = certificate.getEncoded();
      String certificateString = Base64.getEncoder().encodeToString(certificateBytes);
      outputStream.println(certificateString);

      // get other clients certificate and extract public key
      String otherCertString = inputStream.readLine();
      byte[] otherCertBytes = Base64.getDecoder().decode(otherCertString);
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      X509Certificate other_Client_certificate = (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(otherCertBytes));
      other_Client_certificate.checkValidity();

      otherClientPublicKey = other_Client_certificate.getPublicKey();
      security.updateTargetPublicKey(otherClientPublicKey);


    } else if (client.username.equalsIgnoreCase("Bob")) {
      // get other clients certificate and extract public key
      String otherCertString = inputStream.readLine();
      byte[] otherCertBytes = Base64.getDecoder().decode(otherCertString);
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      X509Certificate other_Client_certificate = (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(otherCertBytes));
      other_Client_certificate.checkValidity();

      otherClientPublicKey = other_Client_certificate.getPublicKey();
      security.updateTargetPublicKey(otherClientPublicKey);

      // send this clients certificate certificate
      byte[] certificateBytes = certificate.getEncoded();
      String certificateString = Base64.getEncoder().encodeToString(certificateBytes);
      outputStream.println(certificateString);

    }

    System.out.println("Certificates exchanged and verified.");
  }

public boolean isActive()
{
    return active;
}

public void endSession()
{
    active = false;
}



}
