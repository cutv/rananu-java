package vn.rananu.codec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA {
    public static PrivateKey parseDERPrivateKey(String fileName) throws IOException {
        return parseDERPrivateKey(Files.readAllBytes(Paths.get(fileName)));
    }

    public static PrivateKey parseDERPrivateKey(byte[] encodedKey) {
        try {
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(spec);
        } catch (Throwable cause) {
            throw new RSAException("Unable to parse RSA public key from encodedKey!", cause);
        }
    }

    public static PublicKey parseDERPublicKey(String fileName) throws IOException {
        return parseDERPublicKey(Files.readAllBytes(Paths.get(fileName)));
    }

    public static PublicKey parseDERPublicKey(byte[] encodedKey) {
        try {

            X509EncodedKeySpec x509Spec =
                    new X509EncodedKeySpec(encodedKey);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(x509Spec);
        } catch (Throwable cause) {
            throw new RSAException("Unable to parse RSA public key from encodedKey!", cause);
        }
    }

    public static class RSAException extends RuntimeException {
        public RSAException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
