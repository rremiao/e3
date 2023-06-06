package com.rremiao.security.e3.utils;

import org.springframework.stereotype.Component;

@Component
public class HexToStringUtil {

    public String hexToString(byte[] aNewChallenger) {
        StringBuffer sb = new StringBuffer(aNewChallenger.length  * 2);

        for (int i = 0; i < aNewChallenger.length; i++) {
            int v = aNewChallenger[i] & 0xff;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString().toUpperCase();
    }


    public byte[] hexStringToByteArray(String hexString) {
        int length = hexString.length();
        byte[] byteArray = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }

        return byteArray;
    }

    public String stringToHexString(String str){
 
        char[] chars = str.toCharArray();
   
        StringBuffer hex = new StringBuffer();
        for(int i = 0; i < chars.length; i++){
          hex.append(Integer.toHexString((int)chars[i]));
        }
   
        return hex.toString().toUpperCase();
    }
    
}
