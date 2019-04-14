package ch.obermuhlner.crypto;

import ch.obermuhlner.crypto.internal.SecretKeyService;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Pattern;

public class PasswordService {

    private final int encryptIterations = 1000;
    private final int passwordBytesLength = 64;

    private final SecretKeyService secretKey = new SecretKeyService();

    public String hashPassword(String password) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[12];
            secureRandom.nextBytes(salt);

            byte[] secretKeyBytes = secretKey.getSecretKeyBytes(password, salt, encryptIterations, passwordBytesLength);

            String passwordStorage = encryptIterations + ":" + Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(secretKeyBytes);
            return passwordStorage;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    public boolean verifyPassword(String password, String hashedPassword) {
        try {
            String[] split = hashedPassword.split(Pattern.quote(":"));
            int iterations = Integer.parseInt(split[0]);
            byte[] salt = Base64.getDecoder().decode(split[1]);
            byte[] storedPasswordHash = Base64.getDecoder().decode(split[2]);

            byte[] secretKeyBytes = secretKey.getSecretKeyBytes(password, salt, iterations, passwordBytesLength);

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
}
