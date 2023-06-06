package com.rremiao.security.e3.steps;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.rremiao.security.e3.utils.HexToStringUtil;

@Component
public class StepTwo {

    @Autowired
    private HexToStringUtil hexToStringUtil;
    
    public void readMessage(String key, String message) {
        try {
            String decryptedMessage = new String(decrypt(message, key).getBytes(), StandardCharsets.UTF_8);
            System.out.println("Mensagem Professor: " + decryptedMessage);
            System.out.println();
            String reversedMessage = new StringBuilder(decryptedMessage).reverse().toString();
            System.out.println(encrypt(reversedMessage, key));

            System.out.println();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
    }

    public String encrypt(String plaintext, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(hexToStringUtil.hexStringToByteArray(key), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = randomIv();
        String hexaReverseMessage = hexToStringUtil.stringToHexString(plaintext);
        byte[] hexaReversedMessageBytes = hexToStringUtil.hexStringToByteArray(hexaReverseMessage);        

        IvParameterSpec ivp = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivp);
        byte[] encryptedBytes = cipher.doFinal(hexaReversedMessageBytes);
        return hexToStringUtil.hexToString(iv) + hexToStringUtil.hexToString(encryptedBytes);
    }

    public String decrypt(String ciphertext, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(hexToStringUtil.hexStringToByteArray(key), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = hexToStringUtil.hexStringToByteArray(ciphertext.substring(0, 32));
        byte[] cypherText = hexToStringUtil.hexStringToByteArray(ciphertext.substring(32));

        IvParameterSpec ivp = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivp);

        byte[] decryptedBytes = cipher.doFinal(cypherText);
        return new String(decryptedBytes);
    }

    private byte[] randomIv() {
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }
}
