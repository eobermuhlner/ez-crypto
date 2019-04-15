package ch.obermuhlner.crypto;

import ch.obermuhlner.crypto.v1.EncryptionServiceV1;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class EncryptionServiceTest {
    @Test
    public void testEncryptDecrypt() {
        EncryptionServiceV1 encryptionService = new EncryptionServiceV1();

        String text = "Hello world";
        String password = "secret";
        String encrypted1 = encryptionService.encrypt(text, password);
        String encrypted2 = encryptionService.encrypt(text, password);
        assertNotEquals(encrypted1, encrypted2);

        assertEquals(text, encryptionService.decrypt(encrypted1, password));
        assertEquals(text, encryptionService.decrypt(encrypted2, password));
    }
}
