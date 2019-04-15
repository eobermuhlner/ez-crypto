package ch.obermuhlner.crypto.v1;

import ch.obermuhlner.crypto.CryptoException;
import ch.obermuhlner.crypto.EncryptionService;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class EncryptionServiceV1 implements EncryptionService {

    public static final int VERSION = 1;

    private final int encryptIterations = 1000;

    private final SecretKeyService secretKeyService = new SecretKeyService();

    @Override
    public int getVersion() {
        return VERSION;
    }

    @Override
    public byte[] encrypt(byte[] plain, String key) {
        // https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            byte[] keyBytes = secretKeyService.getSecretKeyBytes(key, iv, encryptIterations, 16);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] encrypted = cipher.doFinal(plain);

            ByteBuffer byteBuffer = ByteBuffer.allocate(4 + 4 + iv.length + encrypted.length);
            byteBuffer.putInt(VERSION);
            byteBuffer.putInt(encryptIterations);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            byte[] output = byteBuffer.array();

            return output;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {            e.printStackTrace();
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encrypted, String key) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);
            int version = byteBuffer.getInt();
            if (version != this.VERSION) {
                throw new IllegalArgumentException("Unknown version: " + version);
            }

            int iterations = byteBuffer.getInt();
            int ivLength = 12;
            byte[] iv = new byte[ivLength];
            byteBuffer.get(iv);
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            byte[] keyBytes = secretKeyService.getSecretKeyBytes(key, iv, iterations, 16);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
            byte[] output = cipher.doFinal(cipherText);

            return output;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {            e.printStackTrace();
            throw new CryptoException(e);
        }
    }
}
