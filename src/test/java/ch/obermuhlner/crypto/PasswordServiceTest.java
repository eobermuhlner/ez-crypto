package ch.obermuhlner.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class PasswordServiceTest {
    @Test
    public void testIsEquals() {
        PasswordService passwordService = new PasswordService();

        assertEquals(true, passwordService.isEquals(toBytes(), toBytes()));
        assertEquals(true, passwordService.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 3)));

        assertEquals(false, passwordService.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 3, 4)));
        assertEquals(false, passwordService.isEquals(toBytes(1, 2, 3, 4), toBytes(1, 2, 3)));

        assertEquals(false, passwordService.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 0)));
        assertEquals(false, passwordService.isEquals(toBytes(1, 2, 3), toBytes(3, 2, 1)));
        assertEquals(false, passwordService.isEquals(toBytes(1, 2, 3), toBytes(9, 7, 8)));
    }

    @Test
    public void testHashVerifyPassword() {
        PasswordService passwordService = new PasswordService();

        String passwordStorage1 = passwordService.hashPassword("secret");
        System.out.println(passwordStorage1);
        String passwordStorage2 = passwordService.hashPassword("secret");
        System.out.println(passwordStorage2);
        assertNotEquals(passwordStorage1, passwordStorage2);

        assertEquals(true, passwordService.verifyPassword("secret", passwordStorage1));
        assertEquals(true, passwordService.verifyPassword("secret", passwordStorage2));

        assertEquals(false, passwordService.verifyPassword("wrong", passwordStorage1));
        assertEquals(false, passwordService.verifyPassword("wrong", passwordStorage2));
    }

    @Test
    public void testEncryptDecrypt() {
        EncryptionService encryptionService = new EncryptionService();

        String text = "Hello world";
        String password = "secret";
        String encrypted1 = encryptionService.encrypt(text, password);
        String encrypted2 = encryptionService.encrypt(text, password);
        assertNotEquals(encrypted1, encrypted2);

        assertEquals(text, encryptionService.decrypt(encrypted1, password));
        assertEquals(text, encryptionService.decrypt(encrypted2, password));
    }

    private byte[] toBytes(int... values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }
}
