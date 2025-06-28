import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

public class SecureServer extends JFrame {
    private static final int PORT = 8080;
    private static final String VALID_USERNAME = "admin";
    private static final String VALID_PASSWORD = "password123";
    
    private JTextArea logArea;
    private JLabel statusLabel;
    private ServerSocket serverSocket;
    private boolean isRunning = false;
    
    // Certificate Authority keys (simulated)
    private KeyPair caKeyPair;
    
    // Server keys for different algorithms
    private KeyPair rsaKeyPair;
    private KeyPair elGamalKeyPair; // Using ECC as ElGamal simulation
    
    public SecureServer() {
        initializeGUI();
        generateKeys();
    }
    
    private void initializeGUI() {
        setTitle("🔒 Secure Server - Cryptography Exercise");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 700);
        setLocationRelativeTo(null);
        
        // Create main panel
        setLayout(new BorderLayout());
        
        // Status panel
        JPanel statusPanel = new JPanel(new FlowLayout());
        statusLabel = new JLabel("🔴 Server Status: Stopped");
        statusLabel.setFont(new Font("Arial", Font.BOLD, 14));
        statusLabel.setForeground(Color.RED);
        statusPanel.add(statusLabel);
        
        // Server info panel
        JPanel infoPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        infoPanel.setBorder(BorderFactory.createTitledBorder("Server Information"));
        infoPanel.add(new JLabel("Port:"));
        infoPanel.add(new JLabel(String.valueOf(PORT)));
        infoPanel.add(new JLabel("Valid Username:"));
        infoPanel.add(new JLabel(VALID_USERNAME));
        infoPanel.add(new JLabel("Valid Password:"));
        infoPanel.add(new JLabel(VALID_PASSWORD));
        
        // Log area
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        logArea.setBackground(new Color(248, 248, 248));
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(880, 400));
        
        // Control panel
        JPanel controlPanel = new JPanel(new FlowLayout());
        JButton startButton = new JButton("▶️ Start Server");
        JButton stopButton = new JButton("⏹️ Stop Server");
        JButton clearButton = new JButton("🗑️ Clear Log");
        JButton showCAButton = new JButton("🔑 Show CA Public Key");
        
        startButton.addActionListener(e -> startServer());
        stopButton.addActionListener(e -> stopServer());
        clearButton.addActionListener(e -> logArea.setText(""));
        showCAButton.addActionListener(e -> showCAPublicKey());
        
        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(clearButton);
        controlPanel.add(showCAButton);
        
        // North panel combining status and info
        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.add(statusPanel, BorderLayout.NORTH);
        northPanel.add(infoPanel, BorderLayout.CENTER);
        
        add(northPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(controlPanel, BorderLayout.SOUTH);
    }
    
    private void generateKeys() {
        try {
            log("🔧 Generating cryptographic keys...");
            
            // Generate CA key pair (for certificate signing)
            KeyPairGenerator caGenerator = KeyPairGenerator.getInstance("RSA");
            caGenerator.initialize(2048);
            caKeyPair = caGenerator.generateKeyPair();
            log("✅ CA key pair generated (RSA 2048-bit)");
            
            // Generate RSA key pair for server
            KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
            rsaGenerator.initialize(2048);
            rsaKeyPair = rsaGenerator.generateKeyPair();
            log("✅ Server RSA key pair generated (2048-bit)");
            
            // Generate ECC key pair for ElGamal simulation
            KeyPairGenerator eccGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            eccGenerator.initialize(ecSpec);
            elGamalKeyPair = eccGenerator.generateKeyPair();
            log("✅ ElGamal key pair generated (simulated with ECC P-256)");
            
        } catch (Exception e) {
            log("❌ Error generating keys: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void showCAPublicKey() {
        if (caKeyPair == null) {
            JOptionPane.showMessageDialog(this, "CA keys not generated yet!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        String caPublicKeyBase64 = Base64.getEncoder().encodeToString(caKeyPair.getPublic().getEncoded());
        
        JDialog dialog = new JDialog(this, "CA Public Key", true);
        dialog.setSize(600, 400);
        dialog.setLocationRelativeTo(this);
        
        JTextArea keyArea = new JTextArea(caPublicKeyBase64);
        keyArea.setEditable(false);
        keyArea.setFont(new Font("Monospaced", Font.PLAIN, 10));
        keyArea.setLineWrap(true);
        keyArea.setWrapStyleWord(true);
        
        JScrollPane scrollPane = new JScrollPane(keyArea);
        
        JPanel buttonPanel = new JPanel();
        JButton copyButton = new JButton("📋 Copy to Clipboard");
        JButton closeButton = new JButton("❌ Close");
        
        copyButton.addActionListener(e -> {
            keyArea.selectAll();
            keyArea.copy();
            JOptionPane.showMessageDialog(dialog, "CA Public Key copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
        });
        
        closeButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(copyButton);
        buttonPanel.add(closeButton);
        
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }
    
    private void startServer() {
        if (isRunning) return;
        
        try {
            serverSocket = new ServerSocket(PORT);
            isRunning = true;
            statusLabel.setText("🟢 Server Status: Running on port " + PORT);
            statusLabel.setForeground(Color.GREEN);
            log("🚀 Server started successfully on port " + PORT);
            log("📡 Waiting for client connections...");
            
            // Start accepting connections in a separate thread
            new Thread(this::acceptConnections).start();
            
        } catch (IOException e) {
            log("❌ Failed to start server: " + e.getMessage());
        }
    }
    
    private void stopServer() {
        if (!isRunning) return;
        
        try {
            isRunning = false;
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            statusLabel.setText("🔴 Server Status: Stopped");
            statusLabel.setForeground(Color.RED);
            log("🛑 Server stopped");
        } catch (IOException e) {
            log("❌ Error stopping server: " + e.getMessage());
        }
    }
    
    private void acceptConnections() {
        while (isRunning) {
            try {
                Socket clientSocket = serverSocket.accept();
                log("📞 New client connected: " + clientSocket.getInetAddress());
                log("━━━━━━━━━━━ STARTING NEW SESSION ━━━━━━━━━━━");
                
                // Handle each client in a separate thread
                new Thread(() -> handleClient(clientSocket)).start();
                
            } catch (IOException e) {
                if (isRunning) {
                    log("❌ Error accepting connection: " + e.getMessage());
                }
            }
        }
    }
    
    private void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
            
            log("📋 Step 1: Processing client connection...");
            
            // Step 2: Receive encryption method selection
            String encryptionChoice = in.readLine();
            log("📨 Step 2: Client selected encryption: " + encryptionChoice);
            
            // Parse encryption selection
            String[] parts = encryptionChoice.split(",");
            String asymmetricAlg = parts[0].trim();
            String symmetricAlg = parts[1].trim();
            
            log("🔐 Asymmetric: " + asymmetricAlg + ", Symmetric: " + symmetricAlg);
            
            // Step 3: Send CA public key first
            log("📤 Step 3: Sending CA public key to client...");
            String caPublicKeyBase64 = Base64.getEncoder().encodeToString(caKeyPair.getPublic().getEncoded());
            // Make sure we send clean Base64 without any extra characters
            caPublicKeyBase64 = caPublicKeyBase64.replaceAll("\\s+", "");
            out.println(caPublicKeyBase64);
            log("✅ CA public key sent (" + caPublicKeyBase64.length() + " chars)");
            
            // Step 4: Build and send certificate
            log("🏗️ Step 4: Building certificate for " + asymmetricAlg);
            String certificate = createCertificate(asymmetricAlg);
            out.println(certificate);
            log("📜 Certificate sent to client");
            
            // Step 5: Receive encrypted AES key
            log("🔑 Step 5: Waiting for encrypted AES key...");
            String encryptedAESKey = in.readLine();
            log("📨 Received encrypted AES key (" + encryptedAESKey.length() + " chars)");
            
            // Decrypt AES key
            SecretKey aesKey = decryptAESKey(encryptedAESKey, asymmetricAlg);
            log("🔓 AES key decrypted successfully (" + (aesKey.getEncoded().length * 8) + "-bit)");
            
            // Step 6: Handle user authentication
            log("🔐 Step 6: Waiting for user credentials...");
            String encryptedCredentials = in.readLine();
            boolean authenticated = authenticateUser(encryptedCredentials, aesKey);
            
            if (authenticated) {
                out.println(encryptMessage("AUTH_SUCCESS", aesKey));
                log("✅ User authenticated successfully");
                
                // Step 7: Send images
                log("🖼️ Step 7: Preparing to send images...");
                sendImages(out, aesKey);
                log("✅ All images sent successfully");
            } else {
                out.println(encryptMessage("AUTH_FAILED", aesKey));
                log("❌ Authentication failed");
            }
            
        } catch (Exception e) {
            log("❌ Error handling client: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
                log("🔌 Client connection closed");
                log("━━━━━━━━━━━ SESSION ENDED ━━━━━━━━━━━");
            } catch (IOException e) {
                log("❌ Error closing client connection: " + e.getMessage());
            }
        }
    }
    
    private String createCertificate(String asymmetricAlg) throws Exception {
        log("📋 Building certificate components...");
        
        // Select appropriate key pair
        KeyPair serverKeyPair = asymmetricAlg.equals("RSA") ? rsaKeyPair : elGamalKeyPair;
        
        // Create certificate data (simple format)
        String serverName = "MySecureServer";
        String publicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
        // Clean the Base64 to ensure no invalid characters
        publicKeyBase64 = publicKeyBase64.replaceAll("\\s+", "");
        String issuerName = "MyFakeCA";
        String algorithm = asymmetricAlg;
        
        // Create certificate data string for hashing
        String certData = "server_name=" + serverName + 
                         "|public_key=" + publicKeyBase64 + 
                         "|issuer_name=" + issuerName + 
                         "|algorithm=" + algorithm;
        
        log("📝 Certificate data created (" + certData.length() + " chars)");
        
        // Create hash of certificate data
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(certData.getBytes("UTF-8"));
        log("🔨 SHA-256 hash calculated (" + hash.length + " bytes)");
        
        // Sign the hash with CA private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(caKeyPair.getPrivate());
        signature.update(hash);
        byte[] signatureBytes = signature.sign();
        
        log("✍️ Digital signature created (" + signatureBytes.length + " bytes)");
        
        // Add signature to certificate
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        // Clean the signature Base64
        signatureBase64 = signatureBase64.replaceAll("\\s+", "");
        String fullCertificate = certData + "|signature=" + signatureBase64;
        
        log("📋 Complete certificate ready (" + fullCertificate.length() + " chars total)");
        return fullCertificate;
    }
    
    private SecretKey decryptAESKey(String encryptedAESKey, String asymmetricAlg) throws Exception {
        KeyPair serverKeyPair = asymmetricAlg.equals("RSA") ? rsaKeyPair : elGamalKeyPair;
        
        if (asymmetricAlg.equals("RSA")) {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
            
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedAESKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            
            return new SecretKeySpec(decryptedBytes, "AES");
        } else {
            // For ElGamal simulation with ECC, we'll use ECIES
            // In a real implementation, you'd use a proper ElGamal library
            throw new UnsupportedOperationException("ElGamal decryption not fully implemented - use RSA");
        }
    }
    
    private boolean authenticateUser(String encryptedCredentials, SecretKey aesKey) throws Exception {
        String decryptedCredentials = decryptMessage(encryptedCredentials, aesKey);
        String[] credentials = decryptedCredentials.split(":", 2);
        
        if (credentials.length == 2) {
            String username = credentials[0];
            String password = credentials[1];
            
            log("🔍 Authenticating user: " + username);
            boolean valid = VALID_USERNAME.equals(username) && VALID_PASSWORD.equals(password);
            log(valid ? "✅ Credentials valid" : "❌ Invalid credentials");
            return valid;
        }
        
        log("❌ Invalid credentials format");
        return false;
    }
    
    private void sendImages(PrintWriter out, SecretKey aesKey) throws Exception {
        log("📸 Creating colorful images...");
        
        // Create larger, more colorful images
        BufferedImage[] images = createColorfulImages();
        String[] imageNames = {"red_gradient.png", "green_spiral.png", "blue_checkerboard.png"};
        
        // Send number of images first
        out.println(encryptMessage(String.valueOf(images.length), aesKey));
        log("📊 Sent image count: " + images.length);
        
        // Send each image
        for (int i = 0; i < images.length; i++) {
            // Convert image to Base64
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(images[i], "PNG", baos);
            byte[] imageBytes = baos.toByteArray();
            String imageBase64 = Base64.getEncoder().encodeToString(imageBytes);
            
            // Create image info
            String imageInfo = imageNames[i] + ":" + imageBase64;
            String encryptedImage = encryptMessage(imageInfo, aesKey);
            out.println(encryptedImage);
            
            log("📤 Sent " + imageNames[i] + " (" + imageBytes.length + " bytes, encrypted to " + encryptedImage.length() + " chars)");
        }
        
        log("🎉 All images sent successfully!");
    }
    
    private BufferedImage[] createColorfulImages() {
        BufferedImage[] images = new BufferedImage[3];
        int size = 150; // Larger images
        
        // Red gradient image
        images[0] = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
        Graphics2D g1 = images[0].createGraphics();
        GradientPaint redGradient = new GradientPaint(0, 0, Color.RED, size, size, Color.PINK);
        g1.setPaint(redGradient);
        g1.fillRect(0, 0, size, size);
        g1.setColor(Color.WHITE);
        g1.setFont(new Font("Arial", Font.BOLD, 16));
        g1.drawString("RED", size/2 - 15, size/2);
        g1.dispose();
        
        // Green spiral image
        images[1] = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = images[1].createGraphics();
        g2.setColor(Color.BLACK);
        g2.fillRect(0, 0, size, size);
        g2.setColor(Color.GREEN);
        g2.setStroke(new BasicStroke(3));
        for (int i = 0; i < 20; i++) {
            int radius = i * 4;
            g2.drawOval(size/2 - radius, size/2 - radius, radius * 2, radius * 2);
        }
        g2.setColor(Color.WHITE);
        g2.setFont(new Font("Arial", Font.BOLD, 16));
        g2.drawString("GREEN", size/2 - 25, size/2);
        g2.dispose();
        
        // Blue checkerboard image
        images[2] = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
        Graphics2D g3 = images[2].createGraphics();
        int squareSize = 15;
        for (int x = 0; x < size; x += squareSize) {
            for (int y = 0; y < size; y += squareSize) {
                if ((x/squareSize + y/squareSize) % 2 == 0) {
                    g3.setColor(Color.BLUE);
                } else {
                    g3.setColor(Color.CYAN);
                }
                g3.fillRect(x, y, squareSize, squareSize);
            }
        }
        g3.setColor(Color.WHITE);
        g3.setFont(new Font("Arial", Font.BOLD, 16));
        g3.drawString("BLUE", size/2 - 20, size/2);
        g3.dispose();
        
        return images;
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
    
    public PublicKey getCAPublicKey() {
        return caKeyPair.getPublic();
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
            new SecureServer().setVisible(true);
        });
    }
}