package ch.obermuhlner.crypto.v1;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Pattern;

public class SecretKeyService {

    public byte[] getSecretKeyBytes(String secret, byte[] salt, int iterations, int length) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/

        PBEKeySpec keySpec = new PBEKeySpec(secret.toCharArray(), salt, iterations, length * 8);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        javax.crypto.SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        byte[] secretKeyBytes = secretKey.getEncoded();
        return secretKeyBytes;
    }
}
