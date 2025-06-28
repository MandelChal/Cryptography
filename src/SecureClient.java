import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class SecureClient extends JFrame {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8080;
    
    private JTextArea logArea;
    private JComboBox<String> asymmetricCombo;
    private JComboBox<String> symmetricCombo;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton connectButton;
    private JPanel imagePanel;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    
    // CA public key (received from server)
    private PublicKey caPublicKey;
    
    public SecureClient() {
        initializeGUI();
        log("🟢 Client initialized and ready to connect");
    }
    
    private void initializeGUI() {
        setTitle("🔒 Secure Client - Cryptography Exercise");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 800);
        setLocationRelativeTo(null);
        
        setLayout(new BorderLayout());
        
        // Create main panels
        JPanel topPanel = createConfigurationPanel();
        JPanel centerPanel = createLogPanel();
        JPanel bottomPanel = createImagePanel();
        
        add(topPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createConfigurationPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("🔧 Configuration & Connection"));
        
        // Status and progress panel
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusLabel = new JLabel("🔴 Status: Ready to connect");
        statusLabel.setFont(new Font("Arial", Font.BOLD, 12));
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Not connected");
        
        statusPanel.add(statusLabel, BorderLayout.WEST);
        statusPanel.add(progressBar, BorderLayout.CENTER);
        
        // Configuration panel
        JPanel configPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Server info
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        JLabel serverInfo = new JLabel("🌐 Server: " + SERVER_HOST + ":" + SERVER_PORT);
        serverInfo.setFont(new Font("Arial", Font.BOLD, 12));
        configPanel.add(serverInfo, gbc);
        
        // Asymmetric encryption selection
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        configPanel.add(new JLabel("🔐 Asymmetric Encryption:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 1;
        asymmetricCombo = new JComboBox<>(new String[]{"RSA", "ElGamal"});
        asymmetricCombo.setToolTipText("Choose asymmetric encryption algorithm");
        configPanel.add(asymmetricCombo, gbc);
        
        // Symmetric encryption selection
        gbc.gridx = 0; gbc.gridy = 2;
        configPanel.add(new JLabel("🔒 Symmetric Encryption:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 2;
        symmetricCombo = new JComboBox<>(new String[]{"AES-256", "AES-128"});
        symmetricCombo.setToolTipText("Choose symmetric encryption algorithm");
        configPanel.add(symmetricCombo, gbc);
        
        // Username
        gbc.gridx = 0; gbc.gridy = 3;
        configPanel.add(new JLabel("👤 Username:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 3;
        usernameField = new JTextField(15);
        usernameField.setText("admin");
        usernameField.setToolTipText("Enter username (default: admin)");
        configPanel.add(usernameField, gbc);
        
        // Password
        gbc.gridx = 0; gbc.gridy = 4;
        configPanel.add(new JLabel("🔑 Password:"), gbc);
        
        gbc.gridx = 1; gbc.gridy = 4;
        passwordField = new JPasswordField(15);
        passwordField.setText("password123");
        passwordField.setToolTipText("Enter password (default: password123)");
        configPanel.add(passwordField, gbc);
        
        // Connect button
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
        connectButton = new JButton("🚀 Connect to Server");
        connectButton.setFont(new Font("Arial", Font.BOLD, 14));
        connectButton.addActionListener(e -> connectToServer());
        configPanel.add(connectButton, gbc);
        
        panel.add(statusPanel, BorderLayout.NORTH);
        panel.add(configPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("📋 Communication Log"));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        logArea.setBackground(new Color(248, 248, 248));
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(980, 300));
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton clearButton = new JButton("🗑️ Clear Log");
        clearButton.addActionListener(e -> logArea.setText(""));
        buttonPanel.add(clearButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createImagePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("🖼️ Received Images"));
        
        imagePanel = new JPanel(new FlowLayout());
        imagePanel.setPreferredSize(new Dimension(980, 200));
        imagePanel.setBackground(Color.WHITE);
        
        JScrollPane scrollPane = new JScrollPane(imagePanel);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void connectToServer() {
        connectButton.setEnabled(false);
        updateStatus("Connecting...", Color.ORANGE, 10);
        
        new Thread(this::performConnection).start();
    }
    
    private void performConnection() {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            
            log("🔌 Connected to server at " + SERVER_HOST + ":" + SERVER_PORT);
            updateStatus("Connected", Color.GREEN, 20);
            
            // Step 1: Send encryption method selection
            String asymmetric = (String) asymmetricCombo.getSelectedItem();
            String symmetric = (String) symmetricCombo.getSelectedItem();
            String encryptionChoice = asymmetric + "," + symmetric;
            
            out.println(encryptionChoice);
            log("📤 Step 2: Sent encryption selection: " + encryptionChoice);
            updateStatus("Encryption selected", Color.GREEN, 30);
            
            // Step 3: Receive CA public key
            log("🔑 Step 3: Receiving CA public key...");
            String caPublicKeyBase64 = in.readLine();
            caPublicKey = loadPublicKeyFromBase64(caPublicKeyBase64, "RSA");
            log("✅ CA public key received and loaded");
            updateStatus("CA key received", Color.GREEN, 40);
            
            // Step 4: Receive and verify certificate
            log("📜 Step 4: Receiving server certificate...");
            String certificateData = in.readLine();
            log("📨 Certificate received (" + certificateData.length() + " characters)");
            
            if (!verifyCertificate(certificateData)) {
                log("❌ Certificate verification failed! Terminating connection.");
                updateStatus("Certificate verification failed", Color.RED, 0);
                return;
            }
            
            log("✅ Certificate verified successfully!");
            updateStatus("Certificate verified", Color.GREEN, 50);
            
            // Step 5: Extract server public key and create AES key
            PublicKey serverPublicKey = extractPublicKeyFromCertificate(certificateData);
            SecretKey aesKey = generateAESKey(symmetric);
            log("🔑 Generated " + symmetric + " key (" + (aesKey.getEncoded().length * 8) + " bits)");
            updateStatus("AES key generated", Color.GREEN, 60);
            
            // Step 6: Encrypt and send AES key
            String encryptedAESKey = encryptAESKey(aesKey, serverPublicKey, asymmetric);
            out.println(encryptedAESKey);
            log("📤 Encrypted AES key sent to server (" + encryptedAESKey.length() + " chars)");
            updateStatus("AES key sent", Color.GREEN, 70);
            
            // Step 7: Send authentication credentials
            String credentials = usernameField.getText() + ":" + new String(passwordField.getPassword());
            String encryptedCredentials = encryptMessage(credentials, aesKey);
            out.println(encryptedCredentials);
            log("🔐 Encrypted credentials sent");
            updateStatus("Credentials sent", Color.GREEN, 80);
            
            // Step 8: Receive authentication response
            log("⏳ Waiting for authentication response...");
            String authResponse = in.readLine();
            String decryptedResponse = decryptMessage(authResponse, aesKey);
            
            if ("AUTH_SUCCESS".equals(decryptedResponse)) {
                log("✅ Authentication successful!");
                updateStatus("Authenticated", Color.GREEN, 90);
                
                // Step 9: Receive images
                log("🖼️ Step 7: Receiving images from server...");
                receiveImages(in, aesKey);
                updateStatus("Images received", Color.GREEN, 100);
                
            } else {
                log("❌ Authentication failed!");
                updateStatus("Authentication failed", Color.RED, 0);
            }
            
        } catch (Exception e) {
            log("❌ Connection error: " + e.getMessage());
            updateStatus("Connection failed", Color.RED, 0);
            e.printStackTrace();
        } finally {
            SwingUtilities.invokeLater(() -> {
                connectButton.setEnabled(true);
                if (progressBar.getValue() != 100) {
                    updateStatus("Ready to connect", Color.BLACK, 0);
                }
            });
        }
    }
    
    private boolean verifyCertificate(String certificateData) {
        try {
            log("🔍 Starting certificate verification...");
            
            // Parse certificate format: field=value|field=value|...
            Map<String, String> certFields = parseCertificate(certificateData);
            
            // Check required fields
            String[] requiredFields = {"server_name", "public_key", "issuer_name", "algorithm", "signature"};
            for (String field : requiredFields) {
                if (certFields.get(field) == null) {
                    log("❌ Certificate missing required field: " + field);
                    return false;
                }
            }
            
            log("✅ Certificate structure validation passed");
            log("📋 Server: " + certFields.get("server_name"));
            log("📋 Issuer: " + certFields.get("issuer_name"));
            log("📋 Algorithm: " + certFields.get("algorithm"));
            
            // Reconstruct certificate data without signature for verification
            String certDataForVerification = "server_name=" + certFields.get("server_name") + 
                                           "|public_key=" + certFields.get("public_key") + 
                                           "|issuer_name=" + certFields.get("issuer_name") + 
                                           "|algorithm=" + certFields.get("algorithm");
            
            // Calculate hash of certificate data
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(certDataForVerification.getBytes("UTF-8"));
            log("🔨 Certificate hash calculated (" + hash.length + " bytes)");
            
            // Verify signature using CA public key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(caPublicKey);
            signature.update(hash);
            
            byte[] signatureBytes = Base64.getDecoder().decode(certFields.get("signature"));
            boolean verified = signature.verify(signatureBytes);
            
            if (verified) {
                log("✅ Digital signature verification successful!");
                return true;
            } else {
                log("❌ Digital signature verification failed!");
                return false;
            }
            
        } catch (Exception e) {
            log("❌ Certificate verification error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    private Map<String, String> parseCertificate(String certificateData) {
        Map<String, String> fields = new HashMap<>();
        String[] pairs = certificateData.split("\\|");
        
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                fields.put(keyValue[0], keyValue[1]);
            }
        }
        
        return fields;
    }
    
    private PublicKey extractPublicKeyFromCertificate(String certificateData) throws Exception {
        Map<String, String> certFields = parseCertificate(certificateData);
        String publicKeyBase64 = certFields.get("public_key");
        String algorithm = certFields.get("algorithm");
        
        return loadPublicKeyFromBase64(publicKeyBase64, algorithm);
    }
    
    private PublicKey loadPublicKeyFromBase64(String publicKeyBase64, String algorithm) throws Exception {
        try {
            // Clean the Base64 string - remove any whitespace and newlines
            String cleanedBase64 = publicKeyBase64.replaceAll("\\s+", "").trim();
            
            // Validate Base64 characters
            if (!cleanedBase64.matches("^[A-Za-z0-9+/]*={0,2}$")) {
                throw new IllegalArgumentException("Invalid Base64 characters found in key data");
            }
            
            byte[] publicKeyBytes = Base64.getDecoder().decode(cleanedBase64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            
            // Handle different algorithms
            String keyAlgorithm = algorithm.equals("ElGamal") ? "EC" : "RSA";
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            
            return keyFactory.generatePublic(spec);
            
        } catch (IllegalArgumentException e) {
            log("❌ Base64 decode error: " + e.getMessage());
            log("❌ Received data: " + publicKeyBase64);
            throw new Exception("Failed to decode public key: " + e.getMessage());
        }
    }
    
    private SecretKey generateAESKey(String symmetric) throws Exception {
        int keySize = symmetric.equals("AES-256") ? 256 : 128;
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }
    
    private String encryptAESKey(SecretKey aesKey, PublicKey serverPublicKey, String asymmetricAlg) throws Exception {
        if (asymmetricAlg.equals("RSA")) {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            
            byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
            return Base64.getEncoder().encodeToString(encryptedKey);
        } else {
            // For ElGamal simulation, we'll throw an exception
            throw new UnsupportedOperationException("ElGamal encryption not fully implemented - please use RSA");
        }
    }
    
    private String encryptMessage(String message, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        
        byte[] encrypted = cipher.doFinal(message.getBytes("UTF-8"));
        byte[] iv = cipher.getIV();
        
        // Combine IV and encrypted data
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }
    
    private String decryptMessage(String encryptedMessage, SecretKey aesKey) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedMessage);
        
        // Extract IV and encrypted data
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, "UTF-8");
    }
    
    private void receiveImages(BufferedReader in, SecretKey aesKey) throws Exception {
        log("📊 Receiving image count...");
        
        // Receive number of images
        String encryptedCount = in.readLine();
        int imageCount = Integer.parseInt(decryptMessage(encryptedCount, aesKey));
        log("📊 Expecting " + imageCount + " images");
        
        SwingUtilities.invokeLater(() -> {
            imagePanel.removeAll();
            imagePanel.revalidate();
            imagePanel.repaint();
        });
        
        // Receive each image
        for (int i = 0; i < imageCount; i++) {
            log("📥 Receiving image " + (i + 1) + "/" + imageCount + "...");
            String encryptedImage = in.readLine();
            String imageInfo = decryptMessage(encryptedImage, aesKey);
            
            // Parse image info (name:base64data)
            String[] parts = imageInfo.split(":", 2);
            if (parts.length == 2) {
                String imageName = parts[0];
                String imageData = parts[1];
                
                displayImage(imageData, imageName, i + 1);
                log("🖼️ Successfully received and displayed: " + imageName);
            } else {
                log("❌ Invalid image format for image " + (i + 1));
            }
        }
        
        SwingUtilities.invokeLater(() -> {
            imagePanel.revalidate();
            imagePanel.repaint();
        });
        
        log("🎉 All " + imageCount + " images received and displayed successfully!");
    }
    
    private void displayImage(String imageData, String imageName, int imageNumber) {
        SwingUtilities.invokeLater(() -> {
            try {
                log("🔄 Processing " + imageName + " (" + imageData.length() + " chars)");
                
                // Decode base64 image data
                byte[] imageBytes = Base64.getDecoder().decode(imageData);
                log("📊 Decoded " + imageBytes.length + " bytes for " + imageName);
                
                ByteArrayInputStream bis = new ByteArrayInputStream(imageBytes);
                BufferedImage image = ImageIO.read(bis);
                
                if (image != null) {
                    log("✅ Successfully loaded " + imageName + " (" + image.getWidth() + "x" + image.getHeight() + " pixels)");
                    
                    // Create image panel
                    JPanel imageContainer = new JPanel(new BorderLayout());
                    imageContainer.setBorder(BorderFactory.createTitledBorder("📷 " + imageName));
                    imageContainer.setPreferredSize(new Dimension(180, 210));
                    
                    // Display image (scale down if too large)
                    int maxSize = 150;
                    Image scaledImage;
                    if (image.getWidth() > maxSize || image.getHeight() > maxSize) {
                        scaledImage = image.getScaledInstance(maxSize, maxSize, Image.SCALE_SMOOTH);
                    } else {
                        scaledImage = image;
                    }
                    
                    ImageIcon icon = new ImageIcon(scaledImage);
                    JLabel imageLabel = new JLabel(icon, JLabel.CENTER);
                    imageContainer.add(imageLabel, BorderLayout.CENTER);
                    
                    // Add image info
                    JLabel infoLabel = new JLabel("<html><center>" + 
                                                image.getWidth() + "x" + image.getHeight() + 
                                                "<br/>" + (imageBytes.length / 1024) + " KB</center></html>");
                    infoLabel.setFont(new Font("Arial", Font.PLAIN, 10));
                    infoLabel.setHorizontalAlignment(JLabel.CENTER);
                    imageContainer.add(infoLabel, BorderLayout.SOUTH);
                    
                    imagePanel.add(imageContainer);
                    
                } else {
                    log("❌ Failed to decode " + imageName + " - ImageIO returned null");
                    createErrorPlaceholder(imageName, "Invalid image format");
                }
            } catch (IllegalArgumentException e) {
                log("❌ Base64 decode error for " + imageName + ": " + e.getMessage());
                createErrorPlaceholder(imageName, "Base64 decode error");
            } catch (IOException e) {
                log("❌ IO error for " + imageName + ": " + e.getMessage());
                createErrorPlaceholder(imageName, "IO error");
            } catch (Exception e) {
                log("❌ Unexpected error for " + imageName + ": " + e.getMessage());
                createErrorPlaceholder(imageName, "Unexpected error");
            }
        });
    }
    
    private void createErrorPlaceholder(String imageName, String errorType) {
        JPanel errorContainer = new JPanel(new BorderLayout());
        errorContainer.setBorder(BorderFactory.createLineBorder(Color.RED, 2));
        errorContainer.setPreferredSize(new Dimension(180, 210));
        errorContainer.setBackground(Color.LIGHT_GRAY);
        
        JLabel errorLabel = new JLabel("<html><center>❌<br/>" + imageName + "<br/>" + errorType + "</center></html>");
        errorLabel.setHorizontalAlignment(JLabel.CENTER);
        errorLabel.setFont(new Font("Arial", Font.BOLD, 12));
        errorContainer.add(errorLabel, BorderLayout.CENTER);
        
        imagePanel.add(errorContainer);
    }
    
    private void updateStatus(String message, Color color, int progress) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("🔄 Status: " + message);
            statusLabel.setForeground(color);
            progressBar.setValue(progress);
            progressBar.setString(message + " (" + progress + "%)");
        });
    }
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = new java.text.SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new SecureClient().setVisible(true);
        });
    }
}