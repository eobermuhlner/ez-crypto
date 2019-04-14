package ch.obermuhlner.crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Pattern;

public class Crypto {

    final int encryptIterations = 1000;
    final int passwordLength = 64;

    public String hashPassword(String password) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[12];
            secureRandom.nextBytes(salt);

            byte[] secretKeyBytes = getSecretBytes(password, salt, encryptIterations, passwordLength);

            String passwordStorage = encryptIterations + ":" + Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(secretKeyBytes);
            return passwordStorage;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    public boolean verifyPassword(String password, String passwordStorage) {
        try {
            String[] split = passwordStorage.split(Pattern.quote(":"));
            int iterations = Integer.parseInt(split[0]);
            byte[] salt = Base64.getDecoder().decode(split[1]);
            byte[] storedPasswordHash = Base64.getDecoder().decode(split[2]);

            byte[] secretKeyBytes = getSecretBytes(password, salt, iterations, passwordLength);

            return isEquals(storedPasswordHash, secretKeyBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    public boolean isEquals(byte[] left, byte[] right) {
        int n = Math.min(left.length, right.length);
        int differences = 0;
        int matches = 0;
        for (int i = 0; i < n; i++) {
            if ((left[i] ^ right[i]) != 0) {
                differences++;
            } else {
                matches++;
            }
        }

        int result = (differences ^ 0) + (matches ^ n) + (left.length ^ right.length);
        return result == 0;
    }

    public String encrypt(String input, String key) {
        byte[] inputBytes = input.getBytes();
        byte[] encryptedBytes = encrypt(inputBytes, key);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encrypted, String key) {
        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
        byte[] decryptedBytes = decrypt(encryptedBytes, key);
        return new String(decryptedBytes);
    }

    public byte[] encrypt(byte[] input, String key) {
        // https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            byte[] keyBytes = getSecretBytes(key, iv, encryptIterations, 16);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] encrypted = cipher.doFinal(input);

            ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + encrypted.length);
            byteBuffer.putInt(encryptIterations);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            byte[] output = byteBuffer.array();

            return output;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {            e.printStackTrace();
            throw new CryptoException(e);
        }
    }

    public byte[] decrypt(byte[] encrypted, String key) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);
            int iterations = byteBuffer.getInt();
            int ivLength = 12;
            byte[] iv = new byte[ivLength];
            byteBuffer.get(iv);
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            byte[] keyBytes = getSecretBytes(key, iv, iterations, 16);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
            byte[] output = cipher.doFinal(cipherText);

            return output;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {            e.printStackTrace();
            throw new CryptoException(e);
        }
    }

    private byte[] getSecretBytes(String password, byte[] salt, int iterations, int length) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/

        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, length * 8);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        byte[] secretKeyBytes = secretKey.getEncoded();
        return secretKeyBytes;
    }
}
