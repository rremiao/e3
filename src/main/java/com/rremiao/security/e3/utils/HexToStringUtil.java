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
    
}
