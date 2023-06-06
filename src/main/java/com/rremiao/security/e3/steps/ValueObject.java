package com.rremiao.security.e3.steps;

import java.math.BigInteger;

import lombok.Data;

@Data
public class ValueObject {
    
    private BigInteger pValue;

    private BigInteger gValue;

    private BigInteger littleA;

    private BigInteger bigA;

    private BigInteger bigB;

    private BigInteger bigV;

    private byte[] bigS;

    private String key;

    private String msgProfessor;
    
    private String msgProfessor2;
    
    public ValueObject withPValue(BigInteger pValue) {
        this.pValue = pValue;
        return this;
    }

    public ValueObject withGValue(BigInteger gValue)  {
        this.gValue = gValue;
        return this;
    }

    public ValueObject withLittleA(BigInteger littleA) {
        this.littleA = littleA;
        return this;
    }

    public ValueObject withBigA(BigInteger bigA) {
        this.bigA = bigA;
        return this;
    }

    public ValueObject withBigS(byte[] bigS) {
        this.bigS = bigS;
        return this;
    }

    public ValueObject withKey(String key) {
        this.key = key;
        return this;
    }

    public ValueObject withMsgProfessor(String msgProfessor) {
        this.msgProfessor = msgProfessor;
        return this;
    }

    public ValueObject withMsgProfessor2(String msgProfessor2) {
        this.msgProfessor2 = msgProfessor2;
        return this;
    }
}
