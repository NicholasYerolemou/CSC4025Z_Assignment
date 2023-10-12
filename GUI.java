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
    private JTextField filePathField;
    private JTextArea captionArea;
    // private JTextArea encodedImageArea;
    private JLabel imagePreviewLabel; // Added for image preview
    private byte[] imageBytes; // To store the image data as bytes
    private JButton sendButton; // Added for sending the image
    private ImageData imageData; // To store the image data as ImageData object

    public GUI(Client client) {
        this.client = client;
        // Initialize the main frame
        frame = new JFrame("Image Caption Application");
        frame.setSize(600, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        // frame.setLayout(new FlowLayout());
        frame.setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Button to select an image
        JButton selectImageButton = new JButton("Select Image");
        // frame.add(selectImageButton);
        topPanel.add(selectImageButton);

        // Text field to display the file path of the selected image
        filePathField = new JTextField(30);
        filePathField.setEditable(false);
        // frame.add(filePathField);
        topPanel.add(filePathField);

        // Image preview label
        imagePreviewLabel = new JLabel();
        frame.add(imagePreviewLabel);

        // Text area for user to input a caption or message
        captionArea = new JTextArea(5, 30);
        captionArea.setWrapStyleWord(true);
        captionArea.setLineWrap(true);
        captionArea.setBorder(BorderFactory.createTitledBorder("Caption"));
        JScrollPane captionScrollPane = new JScrollPane(captionArea);
        // frame.add(captionScrollPane);
        topPanel.add(captionScrollPane);

        // Button to encode the image
        JButton encodeButton = new JButton("Encode Image");
        // frame.add(encodeButton);
        topPanel.add(encodeButton);

        // Button to send the image and the caption
        sendButton = new JButton("Send");
        frame.add(sendButton);

        // Text area to display the encoded image string
        // encodedImageArea = new JTextArea(10, 30);
        // encodedImageArea.setWrapStyleWord(true);
        // encodedImageArea.setLineWrap(true);
        // encodedImageArea.setEditable(false);
        // encodedImageArea.setBorder(BorderFactory.createTitledBorder("Encoded
        // Image"));
        // JScrollPane encodedScrollPane = new JScrollPane(encodedImageArea);
        // frame.add(encodedScrollPane);

        imagePreviewLabel = new JLabel();
        imagePreviewLabel.setBorder(BorderFactory.createTitledBorder("Image Preview"));

        frame.add(topPanel, BorderLayout.NORTH);
        // frame.add(encodedScrollPane, BorderLayout.CENTER);
        frame.add(imagePreviewLabel, BorderLayout.SOUTH);

        // Action listener for the "Select Image" button
        selectImageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectImage();
            }
        });

        // Action listener for the "Encode Image" button
        encodeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                encodeImage();
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
                filePathField.setText(selectedFile.getAbsolutePath());
                imageData = new ImageData(selectedFile);
                imagePreviewLabel.setIcon(imageData.resizeImage());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    // Method to encode the image into a Base64 string
    private void encodeImage() {
        if (imageData != null) {
            String imageString = Base64.getEncoder().encodeToString(imageData.getBytes());
            client.sendMessage(captionArea.getText(), imageData);

            // encodedImageArea.setText(imageString);
        } else {
            JOptionPane.showMessageDialog(frame, "Please select an image first!");
        }
    }

    // Method to send the image and caption
    private void sendImageAndCaption() {
        if (imageData != null) {
            String caption = captionArea.getText();

            client.sendMessage(caption, imageData);

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
            captionArea.setText(message);
        if (image != null) {
            imageBytes = image.getBytes();
            // encodedImageArea.setText(image.encodeImage());
            previewImage(image);
        }
    }
}
