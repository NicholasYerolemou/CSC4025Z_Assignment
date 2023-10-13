import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class Certificate {

    public static X509Certificate certificate;
    private PublicKey CA_PublicKey;
    private SecurityVault security;
    private String username;


  public Certificate (SecurityVault sv,String username)
  {
    security = sv;
    this.username = username;
    getCertificate();
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

        try {
          // get CAs certificate and extract public key
          String CACertString = inputStream.readLine();
          byte[] CACertBytes = Base64.getDecoder().decode(CACertString);
          CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
          X509Certificate CA_certificate = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(CACertBytes));
          CA_certificate.checkValidity();
          System.out.println("CA's certificate verified, extracting public key");
          CA_PublicKey = CA_certificate.getPublicKey();
        } catch (CertificateException e) {
          e.printStackTrace(outputStream);
        }

        // Generate CSR
        PKCS10CertificationRequest csr = generateCSR(security.getKeyPair(), username);

        // Convert CSR to String
        byte[] csrBytes = csr.getEncoded();
        String csrString = Base64.getEncoder().encodeToString(csrBytes);

        // Send CSR to CA
        outputStream.println(csrString);

        // Receive certificate from CA
        String certificateString = inputStream.readLine();
        System.out.println("Received certificate.");

        try { //if the CSR failed they return "Invalid CSR", check for that and reattempt certificate 
          // Convert the certificate from String to X509Certificate
          byte[] certificateBytes = Base64.getDecoder().decode(certificateString);

          CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
          certificate = (X509Certificate) certificateFactory
              .generateCertificate(new ByteArrayInputStream(certificateBytes));
        } catch (Exception e) {
          e.printStackTrace();
        }

      } catch (IOException e) {

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


}
