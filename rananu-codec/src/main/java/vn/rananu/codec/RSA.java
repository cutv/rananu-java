package vn.rananu.codec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class RSA {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PrivateKey parsePEMPrivateKey(File file) {
        try (FileReader fileReader = new FileReader(file)) {
            return parsePEMPrivateKey(fileReader);
        } catch (Throwable cause) {
            throw new RSAException("Unable to parse RSA public key from base64 mudulus and exponent!", cause);
        }
    }

    public static PrivateKey parsePEMPrivateKey(Reader reader) {
        try {
            PEMParser pemParser = new PEMParser(reader);
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPrivateKey(PrivateKeyInfo.getInstance(object));
        } catch (Throwable cause) {
            throw new RSAException("Unable to parse RSA private key from base64 mudulus and exponent!", cause);
        }
    }
    public static PublicKey parsePEMPublicKey(File file) {
        try (FileReader fileReader = new FileReader(file)) {
            return parsePEMPublicKey(fileReader);
        } catch (Throwable cause) {
            throw new RSAException("Unable to parse RSA public key from base64 mudulus and exponent!", cause);
        }
    }
    public static PublicKey parsePEMPublicKey(Reader reader) {
        try {
            PEMParser pemParser = new PEMParser(reader);
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPublicKey((SubjectPublicKeyInfo) object);
        } catch (Throwable cause) {
            throw new RSAException("Unable to parse RSA public key from base64 mudulus and exponent!", cause);
        }
    }

    public static class RSAException extends RuntimeException {
        public RSAException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
