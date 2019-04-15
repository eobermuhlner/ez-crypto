package ch.obermuhlner.crypto;

public class BytesUtil {
    public static byte[] toBytes(int... values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }

}
