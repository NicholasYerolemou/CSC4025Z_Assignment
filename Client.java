import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Client {
  public static final String SERVER_HOST = "localhost"; // Replace with the server's hostname or IP address
  public static final int SERVER_PORT = 12345;

  public static void main(String[] args) {
    try {
      Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
      System.out.println("Connected to the server.");

      // waits for input from the user
      OutputStream output = socket.getOutputStream();
      sendMessage("hello", output);

      // waits for a message from the server
      BufferedReader serverListener = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      Thread responseThread = new Thread(() -> {
        try {
          while (true) {
            String serverMessage = serverListener.readLine();
            if (serverMessage == null) {
              // Server closed the connection
              System.out.println("Server disconnected.");
              disconnect(socket);
              break;
            }
            // we have recieved a message from the server, process that message
            System.out.println("Message recieved");
            receiveMessage(serverMessage);
          }
        } catch (IOException e) {
          e.printStackTrace();
        }
      });
      responseThread.start();

    } catch (IOException e) {
      System.out.println("Failed to connect to server");
      e.printStackTrace();
    }
  }

  private static void sendMessage(String message, OutputStream output) {
    try {
      byte[] msg = (message + "\n").getBytes();
      output.write(msg);
      System.out.println("Sent message");
    } catch (IOException e) {
      System.out.println("Failed to send message");
      e.printStackTrace();
    }
  }

  private static void receiveMessage(String msg) {

    System.out.println("Message recieved: " + msg);

  }

  private static void disconnect(Socket socket) {
    try {
      socket.close();
    } catch (IOException e) {
      System.out.println("Disconnected from server");
      e.printStackTrace();
    }
  }

}
