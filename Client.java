import java.io.*;
import java.net.Socket;

public class Client {
  public static final String SERVER_HOST = "localhost"; // Replace with the server's hostname or IP address
  public static final int SERVER_PORT = 12345;
  private static volatile boolean serverDisconnected = false; // called when the server disconnects

  public static void main(String[] args) {
    try {
      Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
      System.out.println("Connected to the server.");

      // waits for a message from the server
      BufferedReader serverListener = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      Thread responseThread = new Thread(() -> {
        try {
          while (true) {
            String serverMessage = serverListener.readLine();
            if (serverMessage == null) {
              // Server closed the connection
              System.out.println("Server disconnected.");
              socket.close();
              serverDisconnected = true;
              break;
            }
            // we have recieved a message from the server, process that message
            receiveMessage(serverMessage);
          }
        } catch (IOException e) {
          e.printStackTrace();
        }
      });
      responseThread.start();

      // waits for input from the user, sends it to the server
      BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
      OutputStream output = socket.getOutputStream();
      // send client details to the server
      System.out.println("Sent client details");
      sendMessage("Nick", output);
      String userInputLine;
      while (!serverDisconnected) {// ends it the server disconnects
        if (userInput.ready()) {
          userInputLine = userInput.readLine();
          sendMessage(userInputLine, output);
        }
      }

    } catch (IOException e) {
      System.out.println("Failed to connect to server");
      // e.printStackTrace();
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

}
