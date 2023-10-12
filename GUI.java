import javax.swing.*;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.Base64;

public class GUI {

    Client client;
    // Declare GUI components
    private JFrame frame;
    private JTextArea captionArea;
    private JTextArea receivedMessagesArea = new JTextArea(10, 30);
    private JLabel imagePreviewLabel; // Added for image preview
    private ImageData imageData; // To store the image data
    private byte[] imageBytes; // To store the image data as bytes
    private JButton sendButton; // Added for sending the image

    public GUI(Client client) {
        this.client = client;
        // Set the system's native look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Initialize the main frame
        frame = new JFrame("Message Application");
        frame.setSize(600, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.add(new JScrollPane(receivedMessagesArea));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Image preview label
        imagePreviewLabel = new JLabel("", SwingConstants.CENTER);
        imagePreviewLabel.setBorder(BorderFactory.createTitledBorder("Image Preview"));
        frame.add(imagePreviewLabel, BorderLayout.CENTER);

        // Bottom panel for select image, caption, and send
        JPanel bottomPanel = new JPanel(new BorderLayout());

        // Button to select an image
        JButton selectImageButton = new JButton("Select Image");
        selectImageButton.setPreferredSize(new Dimension(100, 10));
        bottomPanel.add(selectImageButton, BorderLayout.WEST);

        // Text area for user to input a caption or message
        captionArea = new JTextArea(2, 10);
        captionArea.setWrapStyleWord(true);
        captionArea.setLineWrap(true);
        captionArea.setBorder(BorderFactory.createTitledBorder("Send a message"));
        captionArea.setFont(new Font("Arial", Font.PLAIN, 14));
        JScrollPane captionScrollPane = new JScrollPane(captionArea);
        bottomPanel.add(captionScrollPane, BorderLayout.CENTER);

        // Button to send the image and the caption
        JButton sendButton = new JButton("Send");
        sendButton.setPreferredSize(new Dimension(80, 10));
        bottomPanel.add(sendButton, BorderLayout.EAST);
        frame.add(bottomPanel, BorderLayout.SOUTH);

        // Color Scheme
        frame.getContentPane().setBackground(new Color(240, 248, 255));
        topPanel.setBackground(new Color(240, 248, 255));

        // Action listener for the "Select Image" button
        selectImageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectImage();
            }
        });

        // Action listener for the "Send" button
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendImageAndCaption();
            }
        });

        // Display the main frame
        frame.setVisible(true);
    }

    // Method to open a file chooser and select an image
    private void selectImage() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            try {
                File selectedFile = fileChooser.getSelectedFile();
                imageData = new ImageData(selectedFile);
                imagePreviewLabel.setIcon(imageData.resizeImage());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    // Method to send the image and caption
    private void sendImageAndCaption() {
        if (imageData != null) {
            String caption = captionArea.getText();

            String structuredMessage = "From:" + client.getName() + caption;
            client.sendMessage(structuredMessage, imageData);

            JOptionPane.showMessageDialog(frame, "Image and caption sent successfully");
        } else {
            JOptionPane.showMessageDialog(frame, "Please select an image first!");
        }
    }

    private void previewImage(ImageData tempImage) {
        imagePreviewLabel.setIcon(tempImage.resizeImage());

    }

    public void setData(String message, ImageData image) {
        if (message != null)
            displayReceivedMessage("Sender", message);
        // captionArea.setText(message);
        if (image != null) {
            imageBytes = image.getBytes();
            // encodedImageArea.setText(image.encodeImage());
            previewImage(image);
        }
    }

    // Method to update the received messages area
    public void displayReceivedMessage(String sender, String message) {
        receivedMessagesArea.append(sender + ": " + message + "\n");
    }

    public void close()
    {
        frame.setVisible(false);
        frame.dispose();
    }

    // Main method to run the GUI application
    public static void main(String[] args) {
    }

}
