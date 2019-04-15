package ch.obermuhlner.crypto;

import ch.obermuhlner.crypto.v1.PasswordServiceV1;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class PasswordServiceTest {
    @Test
    public void testHashVerifyPassword() {
        PasswordService passwordService = new PasswordServiceV1();

        String passwordStorage1 = passwordService.hashPassword("secret");
        String passwordStorage2 = passwordService.hashPassword("secret");
        assertNotEquals(passwordStorage1, passwordStorage2);

        assertEquals(true, passwordService.verifyPassword("secret", passwordStorage1));
        assertEquals(true, passwordService.verifyPassword("secret", passwordStorage2));

        assertEquals(false, passwordService.verifyPassword("wrong", passwordStorage1));
        assertEquals(false, passwordService.verifyPassword("wrong", passwordStorage2));
    }

}
