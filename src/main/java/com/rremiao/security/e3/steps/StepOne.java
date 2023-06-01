package com.rremiao.security.e3.steps;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.rremiao.security.e3.sha256.Sha256;
import com.rremiao.security.e3.utils.HexToStringUtil;

@Component
public class StepOne {

    @Autowired
    private HexToStringUtil hexUtil;

    @Autowired
    private Sha256 sha256;

    public void run () throws NoSuchAlgorithmException {
        ValueObject valueObject = new ValueObject();

        String p = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D18" +
        "9838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FA" +
        "E5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
    
        BigInteger pValue = new BigInteger(p, 16);

        String g = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213" +
            "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D1" + 
            "8E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

        BigInteger gValue = new BigInteger(g, 16);

        BigInteger littleA = new BigInteger("270048722370607679599591040295");

        BigInteger bigA = gValue.modPow(littleA, pValue);

        BigInteger bigB = new BigInteger("07DC8CE070605533BF0ABB3FA4C3961174F93286A202755BA8AA6182AC85F4A15F86D1814103228" + 
            "3BBB04999C6164D1BA98F0946B3C0053CCAFC0E9AEF04FAD3C36DD895DB8725B4696432C1C84DAD36050CC49CBBDD37C7498CCD1F2F82" + 
            "3E9D2E78C628D899322C9991DB1601C07B8E282A443D75EF6383174519889B17D8E6", 16);

        BigInteger bigV =  bigB.modPow(littleA, pValue);

        byte[] bigS = sha256.hashIt(bigV.toByteArray());

        String key = hexUtil.hexToString(bigS);

        valueObject.withPValue(pValue)
                   .withGValue(gValue)
                   .withLittleA(littleA)
                   .withBigA(bigA)
                   .withBigS(bigS)
                   .withKey(key);

        
    }   
    
    public void printer(ValueObject value) {
        System.out.println("P Value: " + value.getPValue());
        System.out.println();
        System.out.println("G Value: " + value.getGValue());
        System.out.println();
        System.out.println("Little A Value:" + value.getLittleA());
        System.out.println();
        System.out.println("Big A Value: " + value.getBigA());
        System.out.println();
        System.out.println("Hex To String BigA: " + hexUtil.hexToString(value.getBigA().toByteArray()));
        System.out.println();
        System.out.println("Key: " + value.getKey());
    }

}
