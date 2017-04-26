/*
 * Universal Password Manager
 * Copyright (C) 2005-2013 Adrian Smith
 *
 * This file is part of Universal Password Manager.
 *   
 * Universal Password Manager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Universal Password Manager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Universal Password Manager; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com._17od.upm.crypto;

import com._17od.upm.util.Util;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.ArrayList;
import java.util.Arrays;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import upm.JavaCardMngr.PCSideCardInterface;



public class EncryptionService {

    //private static final String randomAlgorithm = "SHA2PRNG";
    public static final int FileHandle_LENGTH = 1;
    
    public static final short KeyLengthAES = 32;
    public static final short IVLengthAES = 16;

    private byte[] FileHandle;
    private byte[] KeyFromCard;
    private BufferedBlockCipher encryptCipher;
    private BufferedBlockCipher decryptCipher;
    
    private static PCSideCardInterface InterFaceApplet;

    public EncryptionService(char[] password) throws CryptoException, InvalidPasswordException {
        /*try {
            //if (appIface==null) appIface=new PCSideCardInterface();
            
            //salt=appIface.sendAppletInstruction(PCSideCardInterface.SEND_INS_SETKEY,(byte)0, (byte) 0, databasePinBytes);
            //salt=appIface.sendAppletInstruction("0xb0,0x53",(byte)0, (byte) 0, password);
            //salt = appIface.sendAppletInstruction();
            //this.salt = generateSalt();//Getting from JavaCard
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }*/
        //this.FileHandle = null;
        //initCipher(password);        
        this(password,null);
    }

    public EncryptionService(char[] password, byte[] FileHandle) throws InvalidPasswordException {
        if (InterFaceApplet==null) InterFaceApplet=new PCSideCardInterface();
        this.FileHandle = FileHandle;
        initCipher(password);
    }

    public void initCipher(char[] password) throws InvalidPasswordException {
        
        try{            
            if(FileHandle == null)
            {
               FileHandle=InterFaceApplet.sendAppletInstruction(PCSideCardInterface.SEND_INS_SETKEY,(byte)0, (byte) 0, null , password); 
            }
            KeyFromCard=InterFaceApplet.sendAppletInstruction(PCSideCardInterface.SEND_INS_GETKEY,(byte)0, (byte) 0, FileHandle, password);    
        }catch (InvalidPasswordException ex){
            throw ex;
        }
        
        //PBEParametersGenerator keyGenerator = new PKCS12ParametersGenerator(new SHA256Digest());
       // keyGenerator.init(PKCS12ParametersGenerator.PKCS12PasswordToBytes(password), FileHandle, 20);
        //CipherParameters keyParams = keyGenerator.generateDerivedParameters(256, 128);
        
        KeyParameter aesKey=new KeyParameter(Util.cutArray(KeyFromCard,FileHandle_LENGTH,KeyLengthAES));
        ParametersWithIV keyParams = new ParametersWithIV(aesKey, Util.cutArray(KeyFromCard, FileHandle_LENGTH+KeyLengthAES, IVLengthAES));
        
        encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        encryptCipher.init(true, keyParams);
        decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        decryptCipher.init(false, keyParams);
    }

    //Getting from JavaCard
    /*private byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom saltGen = SecureRandom.getInstance(randomAlgorithm);
        byte pSalt[] = new byte[FileHandle_LENGTH];
        saltGen.nextBytes(pSalt);
        return pSalt;
    }*/

    public byte[] encrypt(byte[] plainText) throws CryptoException {
        byte[] encryptedBytes = new byte[encryptCipher.getOutputSize(plainText.length)];
        int outputLength = encryptCipher.processBytes(plainText, 0, plainText.length, encryptedBytes, 0);
        try {
            outputLength += encryptCipher.doFinal(encryptedBytes, outputLength);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException(e);
        }

        byte[] results = new byte[outputLength];
        System.arraycopy(encryptedBytes, 0, results, 0, outputLength);
        return results;
    }
    
    public byte[] decrypt(byte[] encryptedBytes) throws CryptoException {
        byte[] decryptedBytes = new byte[decryptCipher.getOutputSize(encryptedBytes.length)];
        int outputLength = decryptCipher.processBytes(encryptedBytes, 0, encryptedBytes.length, decryptedBytes, 0);
        try {
            outputLength += decryptCipher.doFinal(decryptedBytes, outputLength);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException(e);
        }

        byte[] results = new byte[outputLength];
        System.arraycopy(decryptedBytes, 0, results, 0, outputLength);
        return results;
    }

    public byte[] getHandle() {
        return FileHandle;
    }
}
