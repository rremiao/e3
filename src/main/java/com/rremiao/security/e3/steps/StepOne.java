package com.rremiao.security.e3.steps;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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

    @Autowired
    private StepTwo stepTwo;

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

        BigInteger bigB = new BigInteger("00842180795CFF4B16A2BD3DF9DC9EE2A1AC100A092F2EBDFEF45BB75D65F7CC1B13CC3974F52" +
            "CAD40D0ADFCDA3F197779132E4F1D240443511DF592D8A64566DD62EA116B38139D5BEC8967D4C952E1E4EC9A83A94DB39C39646C7" +
            "74FDDA41BF73AAB6BFDEEA36990399DC107D59D479567C1538D5FC4CC52ADDFAFAFFED0C208", 16);

        String msgProfessor = "41A3F6C2FDF2F8887F0F8F071B4CE3EF3527B70FF97E1CD27E150ECE2B16FCAEA4C6C0CA6D6C10007D8C8DD" + 
            "8B7C7509EFDB92AC7B2964E0BE2CDE875432C19DC1E2B8F865EA41152E7E7B711CA348F165EFA9C9988485F3690A64EF3B1F0AC76" + 
            "B1B261A64A49B73C3DBBCDBE7289B3CD";

        BigInteger bigV =  bigB.modPow(littleA, pValue);

        byte[] bigS = sha256.hashIt(bigV.toByteArray());

        byte[] keyByte = Arrays.copyOfRange(bigS, 0, 16);

        String key = hexUtil.hexToString(keyByte);

        valueObject.withPValue(pValue)
                   .withGValue(gValue)
                   .withLittleA(littleA)
                   .withBigA(bigA)
                   .withBigS(bigS)
                   .withKey(key);

        
        printer(valueObject); 
        
        stepTwo.readMessage(key, msgProfessor);
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
