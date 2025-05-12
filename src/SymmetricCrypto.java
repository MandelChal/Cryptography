import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.util.Base64;
import java.security.SecureRandom;

/**
 * Symmetric Encryption and Decryption Program
 * Implements DES, 3DES, and AES algorithms
 */
public class SymmetricCrypto {

    /**
     * Function for encrypting text
     *
     * @param algorithm Encryption algorithm (DES, 3DES, or AES)
     * @param key       Encryption key
     * @param plainText Text to encrypt
     * @return Encrypted data as EncryptedData object
     * @throws Exception If there is an error in the encryption process
     */
    public static EncryptedData encrypt(String algorithm, byte[] key, String plainText) throws Exception {
        // Validate key size for algorithm
        validateKeySize(algorithm, key);

        // Prepare appropriate symmetric algorithm
        String transformation = getTransformation(algorithm);

        // Set IV size according to algorithm
        int ivSize = getIvSize(algorithm);

        // Create random initialization vector (IV)
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Create key
        SecretKey secretKey = new SecretKeySpec(key, getAlgorithmName(algorithm));

        // Create encryption instance
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Encrypt the text
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));

        // Create result object
        EncryptedData result = new EncryptedData();
        result.iv = iv;
        result.encryptedData = encryptedBytes;

        // Display results to screen
        System.out.println("Original text: " + plainText);
        System.out.println("Encrypted text (Base64): " + Base64.getEncoder().encodeToString(encryptedBytes));

        // Save result to file
        saveToFile(algorithm + "_encrypted.bin", result);

        return result;
    }

    /**
     * Function for decrypting text
     *
     * @param algorithm     Encryption algorithm (DES, 3DES, or AES)
     * @param key           Decryption key
     * @param encryptedFile File containing the encrypted text
     * @return Decrypted text
     * @throws Exception If there is an error in the decryption process
     */
    public static String decrypt(String algorithm, byte[] key, String encryptedFile) throws Exception {
        // Validate key size for algorithm
        validateKeySize(algorithm, key);

        // Prepare appropriate symmetric algorithm
        String transformation = getTransformation(algorithm);

        // Read data from file
        EncryptedData data = readFromFile(encryptedFile);

        // Create key
        SecretKey secretKey = new SecretKeySpec(key, getAlgorithmName(algorithm));

        // Create decryption instance
        IvParameterSpec ivSpec = new IvParameterSpec(data.iv);
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // Decrypt the text
        byte[] decryptedBytes = cipher.doFinal(data.encryptedData);
        String decryptedText = new String(decryptedBytes, "UTF-8");

        // Display results to screen
        System.out.println("Encrypted text (Base64): " + Base64.getEncoder().encodeToString(data.encryptedData));
        System.out.println("Decrypted text: " + decryptedText);

        // Save to file
        File outputFile = new File(algorithm + "_decrypted.txt");
        FileOutputStream fos = new FileOutputStream(outputFile);
        fos.write(decryptedText.getBytes("UTF-8"));
        fos.close();
        System.out.println("Decrypted text saved to file: " + outputFile.getAbsolutePath());

        return decryptedText;
    }

    /**
     * Check if key size matches the selected algorithm
     */
    private static void validateKeySize(String algorithm, byte[] key) throws Exception {
        if (algorithm.equals("DES")) {
            if (key.length != 8) {
                throw new Exception("Error: DES key must be 8 bytes (64 bits) long");
            }
        } else if (algorithm.equals("DESede") || algorithm.equals("3DES")) {
            if (key.length != 24) {
                throw new Exception("Error: 3DES key must be 24 bytes (192 bits) long");
            }
        } else if (algorithm.equals("AES")) {
            if (key.length != 16 && key.length != 24 && key.length != 32) {
                throw new Exception("Error: AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits) long");
            }
        } else {
            throw new Exception("Error: Unsupported algorithm. Use DES, 3DES, or AES");
        }
    }

    /**
     * Get appropriate IV size for algorithm
     */
    private static int getIvSize(String algorithm) {
        if (algorithm.equals("DES") || algorithm.equals("DESede") || algorithm.equals("3DES")) {
            return 8; // DES and 3DES require 8-byte IV
        } else {
            return 16; // AES requires 16-byte IV
        }
    }

    /**
     * Get algorithm name for SecretKeySpec
     */
    private static String getAlgorithmName(String algorithm) {
        if (algorithm.equals("3DES")) {
            return "DESede";
        }
        return algorithm;
    }

    /**
     * Get appropriate transformation for algorithm
     */
    private static String getTransformation(String algorithm) {
        if (algorithm.equals("3DES")) {
            return "DESede/CBC/PKCS5Padding";
        }
        return algorithm + "/CBC/PKCS5Padding";
    }

    /**
     * Save encrypted data to file
     */
    private static void saveToFile(String fileName, EncryptedData data) throws Exception {
        FileOutputStream fos = new FileOutputStream(fileName);

        // Save IV size
        int ivLength = data.iv.length;
        fos.write(ivLength);

        // Save IV
        fos.write(data.iv);

        // Save encrypted data size
        int dataLength = data.encryptedData.length;
        fos.write((dataLength >> 24) & 0xFF);
        fos.write((dataLength >> 16) & 0xFF);
        fos.write((dataLength >> 8) & 0xFF);
        fos.write(dataLength & 0xFF);

        // Save encrypted data
        fos.write(data.encryptedData);

        fos.close();
        System.out.println("Encrypted text saved to file: " + new File(fileName).getAbsolutePath());
    }

    /**
     * Read encrypted data from file
     */
    private static EncryptedData readFromFile(String fileName) throws Exception {
        FileInputStream fis = new FileInputStream(fileName);

        // Read IV size
        int ivLength = fis.read();

        // Read IV
        byte[] iv = new byte[ivLength];
        fis.read(iv);

        // Read encrypted data size
        int dataLength = 0;
        dataLength = (fis.read() << 24) | (dataLength & 0x00FFFFFF);
        dataLength = (fis.read() << 16) | (dataLength & 0xFF00FFFF);
        dataLength = (fis.read() << 8) | (dataLength & 0xFFFF00FF);
        dataLength = fis.read() | (dataLength & 0xFFFFFF00);

        // Read encrypted data
        byte[] encryptedData = new byte[dataLength];
        fis.read(encryptedData);

        fis.close();

        EncryptedData data = new EncryptedData();
        data.iv = iv;
        data.encryptedData = encryptedData;

        return data;
    }

    /**
     * Internal class for storing encrypted data and initialization vector
     */
    static class EncryptedData {
        byte[] iv;
        byte[] encryptedData;
    }

    /**
     * Main function demonstrating the use of encryption and decryption functions
     */
    public static void main(String[] args) {
        try {
            // Example keys
            byte[] desKey = "12345678".getBytes(); // 8 bytes for DES
            byte[] tripleDesKey = new byte[24]; // 24 bytes for 3DES
            System.arraycopy("123456789012345678901234".getBytes(), 0, tripleDesKey, 0, 24);
            byte[] aesKey = new byte[32]; // 32 bytes for AES-256
            System.arraycopy("12345678901234567890123456789012".getBytes(), 0, aesKey, 0, 32);

            String plainText = "Secret information that needs to be encrypted";

            System.out.println("=== DES Encryption Demo ===");
            EncryptedData desEncrypted = encrypt("DES", desKey, plainText);

            System.out.println("\n=== DES Decryption Demo ===");
            String desDecrypted = decrypt("DES", desKey, "DES_encrypted.bin");

            System.out.println("\n=== 3DES Encryption Demo ===");
            EncryptedData tripleDesEncrypted = encrypt("DESede", tripleDesKey, plainText);

            System.out.println("\n=== 3DES Decryption Demo ===");
            String tripleDesDecrypted = decrypt("DESede", tripleDesKey, "DESede_encrypted.bin");

            System.out.println("\n=== AES-256 Encryption Demo ===");
            EncryptedData aesEncrypted = encrypt("AES", aesKey, plainText);

            System.out.println("\n=== AES-256 Decryption Demo ===");
            String aesDecrypted = decrypt("AES", aesKey, "AES_encrypted.bin");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}