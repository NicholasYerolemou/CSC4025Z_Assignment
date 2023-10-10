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
    private JTextArea encodedImageArea;
    private JLabel imagePreviewLabel; // Added for image preview
    private byte[] imageBytes; // To store the image data as bytes
    private JButton sendButton; // Added for sending the image

    public GUI(Client client) {
        this.client = client;
        // Initialize the main frame
        frame = new JFrame("Image Caption Application");
        frame.setSize(600, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        //frame.setLayout(new FlowLayout());
        frame.setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Button to select an image
        JButton selectImageButton = new JButton("Select Image");
        //frame.add(selectImageButton);
        topPanel.add(selectImageButton);

        // Text field to display the file path of the selected image
        filePathField = new JTextField(30);
        filePathField.setEditable(false);
        //frame.add(filePathField);
        topPanel.add(filePathField);

        //Image preview label
        imagePreviewLabel = new JLabel();
        frame.add(imagePreviewLabel);

        // Text area for user to input a caption or message
        captionArea = new JTextArea(5, 30);
        captionArea.setWrapStyleWord(true);
        captionArea.setLineWrap(true);
        captionArea.setBorder(BorderFactory.createTitledBorder("Caption"));
        JScrollPane captionScrollPane = new JScrollPane(captionArea);
        //frame.add(captionScrollPane);
        topPanel.add(captionScrollPane);

        // Button to encode the image
        JButton encodeButton = new JButton("Encode Image");
        //frame.add(encodeButton);
        topPanel.add(encodeButton);

        //Button to send the image and the caption
        sendButton = new JButton("Send");
        frame.add(sendButton);

        // Text area to display the encoded image string
        encodedImageArea = new JTextArea(10, 30);
        encodedImageArea.setWrapStyleWord(true);
        encodedImageArea.setLineWrap(true);
        encodedImageArea.setEditable(false);
        encodedImageArea.setBorder(BorderFactory.createTitledBorder("Encoded Image"));
        JScrollPane encodedScrollPane = new JScrollPane(encodedImageArea);
        //frame.add(encodedScrollPane);

        imagePreviewLabel = new JLabel();
        imagePreviewLabel.setBorder(BorderFactory.createTitledBorder("Image Preview"));

        frame.add(topPanel, BorderLayout.NORTH);
        frame.add(encodedScrollPane, BorderLayout.CENTER);
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

        //Action listener for the "Send" button
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

                // Read the selected image into a BufferedImage and store it as bytes
                BufferedImage image = ImageIO.read(selectedFile);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ImageIO.write(image, "jpg", baos);
                imageBytes = baos.toByteArray();

                //Define maximum dimensions for the image preview
                int maxWidth = 200;
                int maxHeight =200;
                ImageIcon imageIcon = new ImageIcon(image);
                Image scaledImage = imageIcon.getImage().getScaledInstance(maxWidth, -1, Image.SCALE_SMOOTH);

                if (scaledImage.getHeight(null) > maxHeight) {
                    scaledImage = imageIcon.getImage().getScaledInstance(-1, maxHeight, Image.SCALE_SMOOTH);
                }

                //Calculate the aspect ratio of the image
                double aspectRatio = (double) image.getWidth() / image.getHeight();

                //Calculate new dimensions based on the aspect ratio
                int newWidth = maxWidth;
                int newHeight = (int) (newWidth / aspectRatio);

                if (newHeight > maxHeight) {
                    newHeight = maxHeight;
                    newWidth = (int) (newHeight * aspectRatio);
                }
                imagePreviewLabel.setIcon(new ImageIcon(scaledImage));

            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    // Method to encode the image into a Base64 string
    private void encodeImage() {
        if (imageBytes != null) {
            String imageString = Base64.getEncoder().encodeToString(imageBytes);
            client.sendMessage(imageString);

            encodedImageArea.setText(imageString);
        } else {
            JOptionPane.showMessageDialog(frame, "Please select an image first!");
        }
    }

    //Method to send the image and caption
    private void sendImageAndCaption() {
        if (imageBytes != null) {
            String imageString = Base64.getEncoder().encodeToString(imageBytes);
            String caption = captionArea.getText();

            client.sendMessage(imageString);

            JOptionPane.showMessageDialog(frame, "Image and caption sent successfully");
        } else {
            JOptionPane.showMessageDialog(frame, "Please select an image first!");
        }
    }

    // Main method to run the GUI application
    public static void main(String[] args) {
        // SwingUtilities.invokeLater(new Runnable() {
        //     @Override
        //     public void run() {
        //         new GUI();
        //     }
        // });
    }
}

