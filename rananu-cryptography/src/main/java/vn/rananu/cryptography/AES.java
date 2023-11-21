package vn.rananu.cryptography;


import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class AES {
    public static String encrypt(String data, String key) {
        try {
            byte[] keyArrays = DigestUtils.sha256(key, StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(keyArrays, "AES");

            byte[] ivArrays = Arrays.copyOf(keyArrays, 16);
            IvParameterSpec ivSpec = new IvParameterSpec(ivArrays);

            Cipher cipher;

            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] cipherBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Hex.encodeHexString(cipherBytes);
        } catch (Exception e) {
            throw new IllegalArgumentException("AESCodec encrypt:", e);
        }

    }

    public static String decrypt(String data, String key) {
        try {
            byte[] keyArrays = DigestUtils.sha256(key, StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(keyArrays, "AES");

            byte[] ivArrays = Arrays.copyOf(keyArrays, 16);
            IvParameterSpec ivSpec = new IvParameterSpec(ivArrays);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decryptedText = cipher.doFinal(Hex.decodeHex(data));
            return new String(decryptedText);
        } catch (Exception e) {
            throw new IllegalArgumentException("AESCodec decrypt:", e);
        }
    }
}
