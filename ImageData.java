import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.Base64;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

public class ImageData {
    private int height;
    private int width;
    private byte[] imageBytes;

    public ImageData(File file) {
        try {
            BufferedImage image = ImageIO.read(file);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(image, "jpg", baos);
            imageBytes = baos.toByteArray();
            this.height = image.getHeight();
            this.width = image.getWidth();
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }
    }

    public ImageData(int height, int width, String encodedImage) {
        this.height = height;
        this.width = width;
        byte[] decodedImage = Base64.getDecoder().decode(encodedImage);
        this.imageBytes = decodedImage;
    }

    public byte[] getBytes() {
        return imageBytes;
    }

    public int getHeight() {
        return height;
    }

    public int getWidth() {
        return width;
    }

    public String encodeImage() {
        return Base64.getEncoder().encodeToString(imageBytes);
    }

    public ImageIcon resizeImage() {
        // Define maximum dimensions for the image preview
        int maxWidth = 200;
        int maxHeight = 200;
        ImageIcon imageIcon = new ImageIcon(imageBytes);
        Image scaledImage = imageIcon.getImage().getScaledInstance(maxWidth, -1, Image.SCALE_SMOOTH);

        if (scaledImage.getHeight(null) > maxHeight) {
            scaledImage = imageIcon.getImage().getScaledInstance(-1, maxHeight, Image.SCALE_SMOOTH);
        }
        return new ImageIcon(scaledImage);
    }
}
