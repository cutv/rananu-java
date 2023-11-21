package vn.rananu.cryptography;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestUtils {


    public static String hmacMD5(String key, String data) {
        try {
            byte[] keyBytes = key.getBytes();
            SecretKeySpec signingKey = new SecretKeySpec(keyBytes, "HmacMD5");

            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(data.getBytes());
            return Hex.encodeHexString(rawHmac);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String hmacSHA1(String key, String data) {
        try {
            byte[] keyBytes = key.getBytes();
            SecretKeySpec signingKey = new SecretKeySpec(keyBytes, "HmacSHA1");

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(data.getBytes());
            return  Hex.encodeHexString(rawHmac);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String hmacSHA1(String key, String data, String encoding) {
        try {
            byte[] keyBytes = key.getBytes(encoding);
            SecretKeySpec signingKey = new SecretKeySpec(keyBytes, "HmacSHA1");

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(data.getBytes(encoding));
            return  Hex.encodeHexString(rawHmac);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String encryptMD5(String text) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] array = md.digest(text.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < array.length; i++) {
            sb.append(Integer.toHexString(array[i] & 0xFF | 0x100).substring(1, 3));
        }
        return sb.toString();
    }

    public static byte[] encryptMD5(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(bytes);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String encryptMD5(String text, Charset charset) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] array = md.digest(text.getBytes(charset));
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < array.length; i++) {
                sb.append(Integer.toHexString(array[i] & 0xFF | 0x100).substring(1, 3));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to encryptMD5", e);
        }

    }

    public static String sha256(byte[] array) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] result = md.digest(array);
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < array.length; i++) {
                sb.append(Integer.toHexString(result[i] & 0xFF | 0x100).substring(1, 3));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static byte[] sha256(String text, Charset charset) {
        try {
            byte[] bytes = charset != null ? text.getBytes(charset) : text.getBytes();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(bytes);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String sha512(String text) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-512");
            byte[] bytes = md.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String utf8ToISO88591(String str) {
        return new String(str.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
    }

    public static String iso88591ToUTF8(String str) {
        return new String(str.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    }

    public static String hmacSHA256(String key, String data) {
        try {
            Mac sha256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            sha256.init(keySpec);
            return Hex.encodeHexString(sha256.doFinal(data.getBytes()));
        } catch (Throwable e) {
            throw new IllegalArgumentException("Unable to encode HmacSHA256!", e);
        }
    }

    public static String hmacSHA256(String key, String data, String encoding) {
        try {
            Mac sha256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(encoding), "HmacSHA256");
            sha256.init(keySpec);
            return Hex.encodeHexString(sha256.doFinal(data.getBytes(encoding)));
        } catch (Throwable e) {
            throw new IllegalArgumentException("Unable to encode HmacSHA256!", e);
        }
    }

    public static String hmacSHA512(String key, String data) {
        try {
            Mac sha521 = Mac.getInstance("HmacSHA512");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "HmacSHA512");
            sha521.init(keySpec);
            return Hex.encodeHexString(sha521.doFinal(data.getBytes()));
        } catch (Throwable e) {
            throw new IllegalArgumentException("Unable to encode HmacSHA512!", e);
        }
    }

    public static String hmacSHA512(String key, String data, String encoding) {
        try {
            Mac sha521 = Mac.getInstance("HmacSHA512");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(encoding), "HmacSHA512");
            sha521.init(keySpec);
            return Hex.encodeHexString(sha521.doFinal(data.getBytes(encoding)));
        } catch (Throwable e) {
            throw new IllegalArgumentException("Unable to encode HmacSHA512!", e);
        }
    }
}
