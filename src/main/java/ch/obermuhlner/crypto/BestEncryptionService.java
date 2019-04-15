package ch.obermuhlner.crypto;

import ch.obermuhlner.crypto.v1.EncryptionServiceV1;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class BestEncryptionService implements EncryptionService {

    private final List<EncryptionService> encryptionServices = new ArrayList<>();

    public BestEncryptionService() {
        // add in descending order (highest first)
        encryptionServices.add(new EncryptionServiceV1());
    }

    @Override
    public int getVersion() {
        return encryptionServices.get(0).getVersion();
    }

    @Override
    public byte[] encrypt(byte[] plain, String key) {
        return encryptionServices.get(0).encrypt(plain, key);
    }

    @Override
    public byte[] decrypt(byte[] encrypted, String key) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encrypted);
        int version = byteBuffer.getInt();

        for (EncryptionService encryptionService : encryptionServices) {
            if (version == encryptionService.getVersion()) {
                return encryptionService.decrypt(encrypted, key);
            }
        }

        throw new IllegalArgumentException("Unknown version: " + version);
    }
}
