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

    // Declare GUI components
    private JFrame frame;
    private JTextField filePathField;
    private JTextArea captionArea;
    private JTextArea encodedImageArea;
    private byte[] imageBytes; // To store the image data as bytes

    public GUI() {
        // Initialize the main frame
        frame = new JFrame("Image Caption Application");
        frame.setSize(500, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new FlowLayout());

        // Button to select an image
        JButton selectImageButton = new JButton("Select Image");
        frame.add(selectImageButton);

        // Text field to display the file path of the selected image
        filePathField = new JTextField(30);
        filePathField.setEditable(false);
        frame.add(filePathField);

        // Text area for user to input a caption or message
        captionArea = new JTextArea(5, 30);
        captionArea.setWrapStyleWord(true);
        captionArea.setLineWrap(true);
        JScrollPane captionScrollPane = new JScrollPane(captionArea);
        frame.add(captionScrollPane);

        // Button to encode the image
        JButton encodeButton = new JButton("Encode Image");
        frame.add(encodeButton);

        // Text area to display the encoded image string
        encodedImageArea = new JTextArea(10, 30);
        encodedImageArea.setWrapStyleWord(true);
        encodedImageArea.setLineWrap(true);
        encodedImageArea.setEditable(false);
        JScrollPane encodedScrollPane = new JScrollPane(encodedImageArea);
        frame.add(encodedScrollPane);

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
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    // Method to encode the image into a Base64 string
    private void encodeImage() {
        if (imageBytes != null) {
            String imageString = Base64.getEncoder().encodeToString(imageBytes);
            encodedImageArea.setText(imageString);
        } else {
            JOptionPane.showMessageDialog(frame, "Please select an image first!");
        }
    }

    // Main method to run the GUI application
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new GUI();
            }
        });
    }
}

