package ch.obermuhlner.crypto.v1;

import ch.obermuhlner.crypto.CryptoException;
import ch.obermuhlner.crypto.CryptoUtil;
import ch.obermuhlner.crypto.PasswordService;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Pattern;

public class PasswordServiceV1 implements PasswordService {

    public static final int VERSION = 1;

    private final int encryptIterations = 1000;
    private final int passwordBytesLength = 64;

    private final SecretKeyService secretKey = new SecretKeyService();

    @Override
    public int getVersion() {
        return VERSION;
    }

    @Override
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

    @Override
    public boolean verifyPassword(String password, String hashedPassword) {
        try {
            String[] split = hashedPassword.split(Pattern.quote(":"));
            int iterations = Integer.parseInt(split[0]);
            byte[] salt = Base64.getDecoder().decode(split[1]);
            byte[] storedPasswordHash = Base64.getDecoder().decode(split[2]);

            byte[] secretKeyBytes = secretKey.getSecretKeyBytes(password, salt, iterations, passwordBytesLength);

            return CryptoUtil.isEquals(storedPasswordHash, secretKeyBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }
}
