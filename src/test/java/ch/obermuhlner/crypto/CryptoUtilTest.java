package ch.obermuhlner.crypto;

import ch.obermuhlner.crypto.v1.PasswordServiceV1;
import org.junit.Test;

import static ch.obermuhlner.crypto.BytesUtil.toBytes;
import static org.junit.Assert.assertEquals;

public class CryptoUtilTest {

    @Test
    public void testIsEquals() {
        assertEquals(true, CryptoUtil.isEquals(toBytes(), toBytes()));
        assertEquals(true, CryptoUtil.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 3)));

        assertEquals(false, CryptoUtil.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 3, 4)));
        assertEquals(false, CryptoUtil.isEquals(toBytes(1, 2, 3, 4), toBytes(1, 2, 3)));

        assertEquals(false, CryptoUtil.isEquals(toBytes(1, 2, 3), toBytes(1, 2, 0)));
        assertEquals(false, CryptoUtil.isEquals(toBytes(1, 2, 3), toBytes(3, 2, 1)));
        assertEquals(false, CryptoUtil.isEquals(toBytes(1, 2, 3), toBytes(9, 7, 8)));
    }
}
