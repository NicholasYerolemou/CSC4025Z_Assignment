import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class CA {

    private Socket connectedClient = null;

    public CA() {
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
            // Logic to create a certificate
            String tempName = ""; // Replace with client's name
            String certificate = createCertificate(tempName);
            sendMessage(certificate, out);
        } else if (message.equalsIgnoreCase("1")) {
            // Logic to check the public key against the client's certificate
        } else {
            // Handle unknown message
            System.out.println("Unknown message: " + message);
        }
    }

    private String createCertificate(String clientName) {
        // Logic to create a new certificate for the client
        String tempNewCertificate = clientName + "1";
        System.out.println("Certificate issued.");
        return tempNewCertificate;
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
