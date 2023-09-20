import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
  public static final int PORT = 12345; // Change this to the desired port number

  public static void main(String[] args) {
    try {
      ServerSocket serverSocket = new ServerSocket(PORT);
      System.out.println("Server is listening on port " + PORT);

      // Accept incoming client connections
      while (true) {
        Socket clientSocket = serverSocket.accept();
        System.out.println("Client connected from " + clientSocket.getInetAddress().getHostAddress());

        // Create a separate thread to handle the client connection
        Thread clientThread = new Thread(new ClientHandler(clientSocket));
        clientThread.start();
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  // Define a separate class for handling client connections
  static class ClientHandler implements Runnable {
    private Socket clientSocket;

    public ClientHandler(Socket socket) {
      this.clientSocket = socket;
    }

    @Override
    public void run() {
      try {
        // Handle the client connection here
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);// output stream to write data to the
                                                                                   // client.

        String clientMessage;
        while ((clientMessage = reader.readLine()) != null) {
          // Handle client requests and send responses
          System.out.println("Received from client: " + clientMessage);
          writer.println("OK");
        }

        // Close the client socket when done
        clientSocket.close();
        System.out.println("Client disconnected.");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

}