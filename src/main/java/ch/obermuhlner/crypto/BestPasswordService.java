package ch.obermuhlner.crypto;

import ch.obermuhlner.crypto.v1.PasswordServiceV1;

import java.util.ArrayList;
import java.util.List;

public class BestPasswordService implements PasswordService {

    private final List<PasswordService> passwordServices = new ArrayList<>();

    public BestPasswordService() {
        // add in descending order (highest first)
        passwordServices.add(new PasswordServiceV1());
    }

    @Override
    public int getVersion() {
        return passwordServices.get(0).getVersion();
    }

    @Override
    public String hashPassword(String password) {
        return passwordServices.get(0).hashPassword(password);
    }

    @Override
    public boolean verifyPassword(String password, String hashedPassword) {
        return passwordServices.get(0).verifyPassword(password, hashedPassword);
    }
}
