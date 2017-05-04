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

import com._17od.upm.gui.MainWindow;
import com._17od.upm.util.Translator;
import com._17od.upm.util.Util;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

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

private static final String randomAlgorithm = "SHA1PRNG";
    public static final int SALT_LENGTH = 16;    
    
    public static final int FileHandle_LENGTH = 1;
    
    public static final short KeyLengthAES = 32;
    public static final short IVLengthAES = 16;

    private byte[] FileHandle;
    private byte[] KeyFromCard = new byte[48+1];
    private byte[] ResponseFromCard;
    
    private BufferedBlockCipher encryptCipher;
    private BufferedBlockCipher decryptCipher;
    
    private static PCSideCardInterface InterFaceApplet;
    private byte[] salt;
    byte[] N_1 = new byte [16];
    byte[] N_B = new byte [16];
    
    SecretKeySpec secretKeySpec;
    SecretKeySpec sessionKeySpec;
    
    Cipher cipher;
    Cipher SKcipher;
    
    //private byte AdminPin[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, 0x3D};
    
    private MainWindow mainWindow;

    public EncryptionService(char[] password) throws CryptoException, InvalidPasswordException, Exception {
        this(password,null);
    }

    public EncryptionService(char[] password, byte[] FileHandle) throws InvalidPasswordException, Exception {
        if (InterFaceApplet==null) InterFaceApplet=new PCSideCardInterface();
        this.FileHandle = FileHandle;
        initCipher(password);
    }

    public void initCipher(char[] password) throws InvalidPasswordException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, Exception {
        
        try{
            //Establishing Secure Channel
            SecureChannel(password);
            //SecureChannel();
            
            //Asking Card to be ready with Symm Key
            byte[] Data = new byte[password.length + salt.length];
            System.arraycopy(password.toString().getBytes(), 0, Data, 0, password.length);
            System.arraycopy(salt, 0, Data, password.length, salt.length);            
            InterFaceApplet.SendAppletInstructionSecureChannel(PCSideCardInterface.SEND_INS_GENKEY,(byte)0, (byte) 0, Data); 
            
            //Generate Nounce for PC
            N_1 = generateSalt();
            byte[] Temp = new byte[N_1.length + 16];   
            System.arraycopy(N_1, 0, Temp, 0, N_1.length);
            System.arraycopy("AAAAAAAAAAAAAAAA".getBytes(), 0, Temp, N_1.length, 16);
            byte[] res = new byte[32];            
            cipher.doFinal(Temp, 0, 32, res, 0);
                     
           //Send Ek(Nounce_PC || ID of PC)
           ResponseFromCard = InterFaceApplet.SendAppletInstructionSecureChannel(PCSideCardInterface.SEND_INS_N_1,(byte)0, (byte) 0, res);             
           
           //Received response from Card Nounce_PC || Nounce_Card || ID of Card
           
           //Decrypting Card Nounce
           cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);            
           byte[] res1 = new byte[48]; 
           cipher.doFinal(ResponseFromCard, 0, 48, res1, 0);
           
           //Copying Nounce_Card
           System.arraycopy(res1, 16 , N_B, 0, 16);
            
           cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);           
           
           byte[] res2 = new byte[16]; 

           cipher.doFinal(N_B, 0, 16, res2, 0);
           
            //Send Ek(Nounce_Card) 
           ResponseFromCard = InterFaceApplet.SendAppletInstructionSecureChannel(PCSideCardInterface.SEND_INS_N_B,(byte)0, (byte) 0, res2);                        
           //Checking response from card for Nounce_Card
           if(ResponseFromCard == null)
           {
               //If Nounce_Card not matching throw error
               /*throw exception*/ 
               JOptionPane.showMessageDialog(mainWindow, Translator.translate("SecureChProblem"));
               System.exit(0);
           }
           //Nounce_Card is Verified, then Generate Session Key      
           byte[] SessionKey = new byte [16];
           System.arraycopy(N_1, 0, res, 0, 16);
           System.arraycopy(N_B, 0, res, 16, 16);
           
           //HASH(Nounce_PC || Nounce_Card)
           MessageDigest sha = MessageDigest.getInstance("SHA-1");        
           SessionKey = Arrays.copyOf(sha.digest(res), 16);
           
           //Initialing AES with Session Key
           sessionKeySpec = new SecretKeySpec(SessionKey,"AES");
        
           SKcipher = Cipher.getInstance("AES/ECB/NOPADDING");
        
           SKcipher.init(Cipher.DECRYPT_MODE, sessionKeySpec);
           
           //For New Database
           if(FileHandle == null)
           {   
              //Asking for Handle from Card            
              FileHandle=InterFaceApplet.SendAppletInstruction(PCSideCardInterface.SEND_INS_SETKEY,(byte)0, (byte) 0, null , password); 
           }
           //Asking Key from Card
           byte[] KeyFromCard1=InterFaceApplet.SendAppletInstruction(PCSideCardInterface.SEND_INS_GETKEY,(byte)0, (byte) 0, FileHandle, password);    
           
           //Extracting Key from Card           
           System.arraycopy(KeyFromCard1, (short) 0, KeyFromCard, (short)0, (short)1);
           //Decrypting the key using Session Key
           SKcipher.doFinal(KeyFromCard1, (short)1, (short)(KeyFromCard1.length-1), KeyFromCard, (short)1);
           
        }catch (InvalidPasswordException ex){
            throw ex;
        }
        
        //Encryption/Decryption operation
        //KeyParameter aesKey=new KeyParameter(Util.cutArray(KeyFromCard,FileHandle_LENGTH,KeyLengthAES));
        //ParametersWithIV keyParams = new ParametersWithIV(aesKey, Util.cutArray(KeyFromCard, FileHandle_LENGTH+KeyLengthAES, IVLengthAES));
        
        KeyParameter keyParams = new KeyParameter(Util.cutArray(KeyFromCard,FileHandle_LENGTH,KeyLengthAES));
        
        encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        encryptCipher.init(true, keyParams);
        decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        decryptCipher.init(false, keyParams);
        
    }    

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
    
    private byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom saltGen = SecureRandom.getInstance(randomAlgorithm);
        byte pSalt[] = new byte[SALT_LENGTH];
        saltGen.nextBytes(pSalt);
        return pSalt;
    }

    private void SecureChannel(char[] password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
    //private void SecureChannel() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        
        //Generating Salt
        salt = generateSalt();
        
        byte[] Temp = new byte[password.length + salt.length];
        
        byte[] LongKey = new byte[16];        
     
        System.arraycopy(password.toString().getBytes(), 0, Temp, 0, password.length);
        System.arraycopy(salt, 0, Temp, password.length, salt.length);
        
        //Long Key using PBKDF using 1000 HASH(password || salt)
        MessageDigest sha = MessageDigest.getInstance("SHA-1");        
        //LongKey = Arrays.copyOf(sha.digest(Temp), 16);
        LongKey = Arrays.copyOf(sha.digest(Temp), 20);
        
        for(short i = 0; i < 1000; i++)
        {
            LongKey = Arrays.copyOf(sha.digest(LongKey), 20);
        }       
        LongKey = Arrays.copyOf(sha.digest(LongKey), 16);
        //Initialing AES with Long Key
        secretKeySpec = new SecretKeySpec(LongKey,"AES");
        
        cipher = Cipher.getInstance("AES/ECB/NOPADDING");
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        
        //Validating encrypted text with known plain text with Card 
        
        //byte[] ptdata = "123456789abcdefg".getBytes();

        //byte[] res = new byte[16];
        //cipher.doFinal(ptdata, 0, 16, res, 0);
        
        //System.out.println(res);              
    }   
    
}

