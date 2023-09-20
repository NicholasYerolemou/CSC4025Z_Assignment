import java.io.*;
import java.net.Socket;

public class Client {
  public static final String SERVER_HOST = "localhost"; // Replace with the server's hostname or IP address
  public static final int SERVER_PORT = 12345;
  private static volatile boolean connected = false;
  private static Socket socket;
  private static OutputStream output;

  public static void main(String[] args) {

    connected = connectToServer();
    if (connected) {
      System.out.println("Connected to the server.");
      listenToServer();
      listenForUserInput();
    } else {
      // attempt to connect to the server again
    }

  }

  private static boolean connectToServer() {
    // creates a connection to the server, output stream to that connection and
    // sends initial client info to the server
    try {
      socket = new Socket(SERVER_HOST, SERVER_PORT);

      // create output stream to the server
      try {
        output = socket.getOutputStream();
      } catch (IOException e) {
        System.out.println("Unable to create output stream to server");
        e.printStackTrace();
      }

      // send initial client detials to server
      sendMessage("Nick", output);
      return true;

    } catch (IOException e) {
      System.out.println("Failed to connect to server");
      e.printStackTrace();
      return false;
    }

  }

  private static void listenForUserInput() {
    // waits for input from the user, sends it to the server
    BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
    String userInputLine;
    while (connected) {// ends it the server disconnects
      try {
        if (userInput.ready()) {
          userInputLine = userInput.readLine();
          sendMessage(userInputLine, output);
        }
      } catch (IOException e) {
        System.out.println("");
        e.printStackTrace();
      }
    }

  }

  private static void listenToServer() {
    // creates a seperate thread that listens for a message from the server
    BufferedReader serverListener;
    try {
      serverListener = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    } catch (IOException e) {
      System.out.println("Unable to create server listener in client");
      e.printStackTrace();
      return;
    }

    Thread responseThread = new Thread(() -> {
      try {
        while (true) {
          String serverMessage = serverListener.readLine();
          if (serverMessage == null) {
            // Server closed the connection
            System.out.println("Server disconnected.");
            socket.close();
            connected = false;
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

  }

  private static void sendMessage(String message, OutputStream output) {
    try {
      byte[] msg = (message + "\n").getBytes();
      output.write(msg);
    } catch (IOException e) {
      System.out.println("Failed to send message");
      e.printStackTrace();
    }
  }

  private static void receiveMessage(String msg) {

    System.out.println("Message recieved: " + msg);

  }

}
