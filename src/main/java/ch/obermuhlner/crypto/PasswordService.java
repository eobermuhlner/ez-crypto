package ch.obermuhlner.crypto;

public interface PasswordService {

    int getVersion();

    String hashPassword(String password);

    boolean verifyPassword(String password, String hashedPassword);

}
