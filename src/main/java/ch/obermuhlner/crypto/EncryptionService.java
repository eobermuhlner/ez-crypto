package ch.obermuhlner.crypto;

import java.util.Base64;

public interface EncryptionService {

    int getVersion();

    default String encrypt(String plain, String key) {
        byte[] inputBytes = plain.getBytes();
        byte[] encryptedBytes = encrypt(inputBytes, key);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    byte[] encrypt(byte[] plain, String key);

    default String decrypt(String encrypted, String key) {
        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
        byte[] decryptedBytes = decrypt(encryptedBytes, key);
        return new String(decryptedBytes);
    }

    byte[] decrypt(byte[] encrypted, String key);

}
