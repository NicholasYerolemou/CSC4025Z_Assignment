import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CA {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Socket connectedClient = null;

    public CA() {
        generateKeys();
        listenForConnections();
    }

private void generateKeys()
    {
         //generate this clients pub and private keys
    KeyPairGenerator keyPairGenerator;
    try {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    } catch (NoSuchAlgorithmException e) {
        System.out.println("Unable to create key pair generator.");
        e.printStackTrace();
    }
    }

private void listenForConnections()
{
    int PORT = 12346;
        try {
            ServerSocket CASocket = new ServerSocket(PORT);
            System.out.println("The CA is listening on port " + PORT);

            while (true) {
                Socket targetSocket = CASocket.accept();
                connectedClient = targetSocket;
                System.out.println("Client connected from " + targetSocket.getInetAddress().getHostAddress() + ".");

                listenForMessages(targetSocket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
}

private void listenForMessages(Socket targetSocket) {
    System.out.println("Listening for user input and messages.");

    try (BufferedReader in = new BufferedReader(new InputStreamReader(targetSocket.getInputStream()));
            PrintWriter out = new PrintWriter(targetSocket.getOutputStream(), true)) {

        String receivedMessage = in.readLine();

        if (receivedMessage != null) {
            receiveMessage(receivedMessage, out);
        }

    } catch (IOException e) {
        e.printStackTrace();
    }
}

private void receiveMessage(String message, PrintWriter out) {
    if (message.equalsIgnoreCase("0")) {
        System.out.println("Client requested a new certificate.");
        issueCertificate();
    } else if (message.equalsIgnoreCase("1")) {
        // Logic to check the public key against the client's certificate
    } else {
        // Handle unknown message
        System.out.println("Unknown message: " + message);
    }
}


private void issueCertificate()
{
    //provide CA's pub key to the client 
    try (OutputStream outputStream = connectedClient.getOutputStream()) {
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        // Send the length of the public key bytes followed by the bytes themselves
        byte[] publicKeyBytes = publicKey.getEncoded();
        dataOutputStream.writeInt(publicKeyBytes.length);
        dataOutputStream.write(publicKeyBytes);
        dataOutputStream.flush();
        
    } catch (IOException e) {
        System.out.println("Failed to create output stream to client when issueing client certificate");
        e.printStackTrace();
    }


    //check if the client already has a certificate
    //otherwise create one and send it to them
}
private void createCertificate() {
    // Logic to create a new certificate for the client
    System.out.println("Certificate issued.");
    
}

private void sendMessage(String message, PrintWriter out) {
    out.println(message); // Send a message to the client
    try {
        connectedClient.close();
    } catch (IOException e) {
        System.out.println("Could not close connection with client.");
        e.printStackTrace();
    } // Close the connection after sending the response
}

public static void main(String[] args) {
        CA ca = new CA();
    }
}
