package ch.obermuhlner.crypto;

public class CryptoUtil {

    public static boolean isEquals(byte[] left, byte[] right) {
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
