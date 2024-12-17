package com.kn.core.utils.encry;


import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;

public class CreateSecretKey {
    public static final String KEY_ALGORITHM = "RSA";
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;

    public CreateSecretKey() {
    }

    public static PublicKey getPublicKey(String key) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] keyBytes = decoder.decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] keyBytes = decoder.decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static byte[] sign(byte[] data, String privateKey) throws Exception {
        PrivateKey priK = getPrivateKey(privateKey);
        Signature sig = Signature.getInstance("MD5withRSA");
        sig.initSign(priK);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(byte[] data, byte[] sign, String publicKey) throws Exception {
        PublicKey pubK = getPublicKey(publicKey);
        Signature sig = Signature.getInstance("MD5withRSA");
        sig.initVerify(pubK);
        sig.update(data);
        return sig.verify(sign);
    }

    public static byte[] encrypt(byte[] plainText, String publicKey) throws Exception {
        PublicKey publicK = getPublicKey(publicKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(1, publicK);
        int inputLen = plainText.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;

        for(int i = 0; inputLen - offSet > 0; offSet = i * 117) {
            byte[] cache;
            if (inputLen - offSet > 117) {
                cache = cipher.doFinal(plainText, offSet, 117);
            } else {
                cache = cipher.doFinal(plainText, offSet, inputLen - offSet);
            }

            out.write(cache, 0, cache.length);
            ++i;
        }

        byte[] encryptText = out.toByteArray();
        out.close();
        return encryptText;
    }

    public static byte[] decrypt(byte[] encryptText, String privateKey) throws Exception {
        PrivateKey privateK = getPrivateKey(privateKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(2, privateK);
        int inputLen = encryptText.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;

        for(int i = 0; inputLen - offSet > 0; offSet = i * 128) {
            byte[] cache;
            if (inputLen - offSet > 128) {
                cache = cipher.doFinal(encryptText, offSet, 128);
            } else {
                cache = cipher.doFinal(encryptText, offSet, inputLen - offSet);
            }

            out.write(cache, 0, cache.length);
            ++i;
        }

        byte[] plainText = out.toByteArray();
        out.close();
        return plainText;
    }

    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化随机数生成器，提高密钥的随机性
        SecureRandom secRandom = new SecureRandom();
        secRandom.setSeed("random seed".getBytes());
        keyPairGen.initialize(1024,secRandom);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap(2);
        Base64.Encoder encoder = Base64.getEncoder();
        keyMap.put("RSAPublicKey", encoder.encodeToString(publicKey.getEncoded()));
        keyMap.put("RSAPrivateKey", encoder.encodeToString(privateKey.getEncoded()));
        System.out.println(keyMap.get("RSAPublicKey"));
        System.out.println(keyMap.get("RSAPrivateKey"));
        return keyMap;
    }

    public static String decryptByPrivateKey(String text, String privatekey) throws Exception {
        try {
            PrivateKey privateK = getPrivateKey(privatekey);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(2, privateK);
            byte[] result = cipher.doFinal(Base64.getDecoder().decode(text));
            return new String(result);
        } catch (Exception var5) {
            Exception e = var5;
            e.printStackTrace();
            throw new Exception("参数解析时出现错误");
        }
    }

    public static String ecryptByPublicKey(String text, String publicKey) throws Exception {
        try {
            PublicKey publicK = getPublicKey(publicKey);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(1, publicK);
            byte[] result = cipher.doFinal(text.getBytes());
            return new String(Base64.getEncoder().encode(result));
        } catch (Exception var5) {
            Exception e = var5;
            e.printStackTrace();
            throw new Exception("参数解析时出现错误");
        }
    }

    public static void main(String[] args) throws Exception {
        try {
            initKey();
        } catch (Exception var2) {
            Exception e = var2;
            e.printStackTrace();
        }

    }
}
