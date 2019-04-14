package ch.obermuhlner.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class CryptoTest {
    @Test
    public void testIsEquals() {
        Crypto crypto = new Crypto();

        assertEquals(true, crypto.isEquals(toBytes(), toBytes()));
        assertEquals(true, crypto.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 3)));

        assertEquals(false, crypto.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 3, 4)));
        assertEquals(false, crypto.isEquals(toBytes(1, 2, 3, 4), toBytes(1, 2, 3)));

        assertEquals(false, crypto.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 0)));
        assertEquals(false, crypto.isEquals(toBytes(1, 2, 3), toBytes(3, 2, 1)));
        assertEquals(false, crypto.isEquals(toBytes(1, 2, 3), toBytes(9, 7, 8)));
    }

    @Test
    public void testHashVerifyPassword() {
        Crypto crypto = new Crypto();

        String passwordStorage1 = crypto.hashPassword("secret");
        System.out.println(passwordStorage1);
        String passwordStorage2 = crypto.hashPassword("secret");
        System.out.println(passwordStorage2);
        assertNotEquals(passwordStorage1, passwordStorage2);

        assertEquals(true, crypto.verifyPassword("secret", passwordStorage1));
        assertEquals(true, crypto.verifyPassword("secret", passwordStorage2));

        assertEquals(false, crypto.verifyPassword("wrong", passwordStorage1));
        assertEquals(false, crypto.verifyPassword("wrong", passwordStorage2));
    }

    @Test
    public void testEncryptDecrypt() {
        Crypto crypto = new Crypto();

        String text = "Hello world";
        String password = "secret";
        String encrypted1 = crypto.encrypt(text, password);
        String encrypted2 = crypto.encrypt(text, password);
        assertNotEquals(encrypted1, encrypted2);

        assertEquals(text, crypto.decrypt(encrypted1, password));
        assertEquals(text, crypto.decrypt(encrypted2, password));
    }

    private byte[] toBytes(int... values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }
}
