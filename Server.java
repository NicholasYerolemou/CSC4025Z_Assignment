import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Server {
  public static final int PORT = 12345; // Change this to the desired port number
  public static Map<String, ClientRecord> clientRecords = new HashMap<>(); // HashMap to store client records by name

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
        PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

        // System.out.println("Length of hasmap " + clientRecords.size());

        // Create a new client record
        String clientDetails = reader.readLine();
        String[] clientDetailsArr = clientDetails.split(",");
        String name = clientDetailsArr[0];
        String clientIP = clientSocket.getInetAddress().getHostAddress();
        ClientRecord thisClient;

        synchronized (clientRecords) {
          if (clientRecords.containsKey(name))// this client has connected before
          {
            thisClient = clientRecords.get(name);
            thisClient.connected();
            System.out.println("Loaded existing client record");
          } else {// new client
            thisClient = new ClientRecord(clientIP, name);
            clientRecords.put(name, thisClient);
            System.out.println("Created new client record for: " + name);
          }
        }

        String clientMessage;
        while ((clientMessage = reader.readLine()) != null) {
          if (clientMessage.equalsIgnoreCase("exit")) {
            writer.println("Ending connection with server");
            clientSocket.close();
            break;
          }

          // Handle client requests and send responses
          System.out.println("Received from client: " + clientMessage);
          writer.println("Thank you for your message, " + clientMessage + ", - Server");
          thisClient.addMessage(clientMessage);
        }

        thisClient.disconnect(); // Mark the client as disconnected
        clientSocket.close();
        System.out.println("Client disconnected.");

      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  private static class ClientRecord {
    private String IP;
    private String name;
    private List<String> messages = new ArrayList<>();
    private boolean isConnected = true; // Initially, the client is considered connected

    public ClientRecord(String ip, String name) {
      this.IP = ip;
      this.name = name;
    }

    public void addMessage(String msg) {
      messages.add(msg);
    }

    public void disconnect() {
      isConnected = false;
    }

    public void connected() {
      isConnected = true;
    }

    public boolean isConnected() {
      return isConnected;
    }
  }

}
