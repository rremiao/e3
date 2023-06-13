package com.rremiao.security.e3.sha256;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.stereotype.Component;

@Component
public class Sha256 {

    //Metodo de Hash
    public byte[] hashIt(byte[] lastPiece) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(lastPiece);
    }
}
