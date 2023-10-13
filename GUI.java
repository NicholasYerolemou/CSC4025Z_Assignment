import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.awt.image.BufferedImage;

public class GUI {

    Client client;
    private JFrame frame;
    private JTextArea captionArea;
    private JPanel chatPanel; // Panel to hold chat bubbles
    private JScrollPane chatScrollPane;
    private ImageData imageData;
    private ArrayList<JPanel> chatBubbles;
    private JDialog imagePreviewDialog; // Dialog for image preview
    private JLabel imagePreviewLabel; // JLabel to display the image

    public GUI(Client client) {
        this.client = client;
        chatBubbles = new ArrayList<>();
        frame = new JFrame("Message Application");
        frame.setSize(600, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        // Create a chat panel to hold chat bubbles
        chatPanel = new JPanel();
        chatPanel.setLayout(new BoxLayout(chatPanel, BoxLayout.Y_AXIS));
        chatScrollPane = new JScrollPane(chatPanel);
        chatScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // Create an image preview dialog
        imagePreviewDialog = new JDialog(frame, "Image Preview", Dialog.ModalityType.APPLICATION_MODAL);
        imagePreviewDialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        imagePreviewDialog.setSize(400, 400);

        // Create a panel to hold the image preview
        JPanel imagePreviewPanel = new JPanel(new BorderLayout());
        imagePreviewLabel = new JLabel(); // JLabel to display the image

        imagePreviewPanel.add(imagePreviewLabel, BorderLayout.CENTER);
        imagePreviewDialog.add(imagePreviewPanel);

        // Create a bottom panel for selecting image, caption, and sending
        JPanel bottomPanel = createBottomPanel();
        JPanel headerPanel = createHeaderSection();

        frame.add(headerPanel, BorderLayout.NORTH);
        frame.add(chatScrollPane, BorderLayout.CENTER);
        frame.add(bottomPanel, BorderLayout.SOUTH);

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Display the main frame
        frame.setVisible(true);
    }

    private void showImagePreview(ImageData imageData) {
        // Set the image in the image preview label
        ImageIcon imageIcon = imageData.resizeImage(); // Use your image data
        imagePreviewLabel.setIcon(imageIcon);

        // Show the image preview dialog
        imagePreviewDialog.pack();
        imagePreviewDialog.setLocationRelativeTo(frame);
        imagePreviewDialog.setVisible(true);
        // imagePreviewDialog.
    }

    private JPanel createHeaderSection() {
        JPanel headerPanel = new JPanel(new GridBagLayout());
        headerPanel.setBackground(Color.LIGHT_GRAY);

        GridBagConstraints leftLabelConstraints = new GridBagConstraints();
        leftLabelConstraints.anchor = GridBagConstraints.WEST;
        leftLabelConstraints.weightx = 1.0;
        leftLabelConstraints.insets = new Insets(5, 5, 5, 0);

        GridBagConstraints rightLabelConstraints = new GridBagConstraints();
        rightLabelConstraints.anchor = GridBagConstraints.EAST;
        rightLabelConstraints.weightx = 1.0;
        rightLabelConstraints.insets = new Insets(5, 0, 5, 5);

        String leftLabelText = "Bob";
        if (client.getName().toLowerCase().equals("bob"))
            leftLabelText = "Alice";
        else
            leftLabelText = "Bob";

        // Left-aligned word
        JLabel leftLabel = new JLabel(leftLabelText);
        headerPanel.add(leftLabel, leftLabelConstraints);

        // Right-aligned word
        JLabel rightLabel = new JLabel(client.getName());
        headerPanel.add(rightLabel, rightLabelConstraints);
        return headerPanel;
    }

    private JPanel createBottomPanel() {
        JPanel bottomPanel = new JPanel(new BorderLayout());

        JButton selectImageButton = new JButton("Select Image");
        selectImageButton.setPreferredSize(new Dimension(100, 10));

        captionArea = new JTextArea(2, 10);
        captionArea.setWrapStyleWord(true);
        captionArea.setLineWrap(true);
        captionArea.setBorder(BorderFactory.createTitledBorder("Send a message"));
        captionArea.setFont(new Font("Arial", Font.PLAIN, 14));
        JScrollPane captionScrollPane = new JScrollPane(captionArea);

        JButton sendButton = new JButton("Send");
        sendButton.setPreferredSize(new Dimension(80, 10));

        bottomPanel.add(selectImageButton, BorderLayout.WEST);
        bottomPanel.add(captionScrollPane, BorderLayout.CENTER);
        bottomPanel.add(sendButton, BorderLayout.EAST);

        selectImageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectImage();
            }
        });

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendImageAndCaption();
            }
        });

        return bottomPanel;
    }

    private void selectImage() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            try {
                File selectedFile = fileChooser.getSelectedFile();
                imageData = new ImageData(selectedFile);
                // Use SwingWorker to load and display the image asynchronously
                SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        try {
                            imageData = new ImageData(selectedFile);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                        return null;
                    }

                    @Override
                    protected void done() {
                        if (imageData != null) {
                            showImagePreview(imageData);
                        }
                    }
                };

                worker.execute();
                // showImagePreview(imageData);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    private void sendImageAndCaption() {
        String caption = captionArea.getText();
        if (caption.length() == 0 && imageData == null)
            return;

        if (imageData != null) {
            client.sendMessage(caption, imageData);
        } else {
            client.sendMessage(caption, null);
        }

        updateChatDisplay(caption, false, imageData);
        captionArea.setText(""); // Clear the caption area
        imageData = null;
    }

    public void updateChatDisplay(String message, boolean isSender, ImageData image) {
        if (message.length() > 0) {
            // Create a ChatBubble with the message and sender flag
            ChatBubble chatBubble = new ChatBubble(message, isSender, chatPanel.getWidth());

            // Add the ChatBubble to the chat panel
            chatBubbles.add(chatBubble);
            chatPanel.add(chatBubble);
        }
        if (image != null) {
            ChatBubble chatBubbleImage = new ChatBubble(image, isSender, chatPanel.getWidth());
            chatBubbles.add(chatBubbleImage);
            chatPanel.add(chatBubbleImage);
        }

        // Repaint and revalidate the chat panel to update the display
        chatPanel.revalidate();
        chatPanel.repaint();
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JScrollBar verticalScrollBar = chatScrollPane.getVerticalScrollBar();
                verticalScrollBar.setValue(verticalScrollBar.getMaximum());
            }
        });
    }

    public void setData(String message, ImageData image) {
        imageData = image;
        updateChatDisplay(message, true, image);
        imageData = null;
    }
}

class ChatBubble extends JPanel {
    public ChatBubble(String message, boolean isSender, int width) {
        int height = 50;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 6, 2, 6));

        JTextArea messageArea = new JTextArea(message);
        messageArea.setWrapStyleWord(true);
        messageArea.setLineWrap(true);
        messageArea.setMargin(new Insets(10, 5, 10, 5));
        messageArea.setEditable(false);
        messageArea.setCursor(null);

        if (isSender) {
            messageArea.setBackground(new Color(173, 216, 230)); // Light blue for sender
            this.setBackground(new Color(173, 216, 230)); // Light blue for sender
            messageArea.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
        } else {
            messageArea.setBackground(new Color(240, 248, 255)); // Light blue for receiver
            this.setBackground(new Color(240, 248, 255)); // Light blue for receiver
            messageArea.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
        }
        this.setPreferredSize(new Dimension(width, height));
        this.setMaximumSize(this.getPreferredSize());
        this.setMinimumSize(this.getPreferredSize());
        add(messageArea);
    }

    public ChatBubble(ImageData thumbnail, boolean isSender, int width) {
        int height = 210;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(2, 10, 10, 10));

        if (thumbnail != null) {
            JLabel thumbnailLabel = new JLabel(thumbnail.resizeImage());
            thumbnailLabel.setAlignmentX(Component.RIGHT_ALIGNMENT);

            if (isSender) {
                this.setBackground(new Color(173, 216, 230)); // Light blue for sender
                add(thumbnailLabel, BorderLayout.WEST);
            } else {
                this.setBackground(new Color(240, 248, 255)); // Light blue for receiver
                add(thumbnailLabel, BorderLayout.EAST);
            }
        }

        this.setPreferredSize(new Dimension(width, height));
        this.setMaximumSize(this.getPreferredSize());
        this.setMinimumSize(this.getPreferredSize());
    }
}
