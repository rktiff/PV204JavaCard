package JavaCardApplet;

//package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SimpleApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET                = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_GENKEY                     = (byte) 0x50;
    final static byte INS_N_1                        = (byte) 0x51;
    final static byte INS_N_B                        = (byte) 0x54;
    final static byte INS_SETKEY                     = (byte) 0x52;
    final static byte INS_GETKEY                     = (byte) 0x53;
    
    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_BAD_Handle                 = (short) 0x6715;
    final static short SW_WRONG_N_B                  = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;
    
    final static short SW_Exception                     = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException           = (short) 0xff03;
    final static short SW_ArrayStoreException           = (short) 0xff04;
    final static short SW_NullPointerException          = (short) 0xff05;
    final static short SW_NegativeArraySizeException    = (short) 0xff06;
    final static short SW_CryptoException_prefix        = (short) 0xf100;
    final static short SW_SystemException_prefix        = (short) 0xf200;
    final static short SW_PINException_prefix           = (short) 0xf300;
    final static short SW_TransactionException_prefix   = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix   = (short) 0xf500;

    final static byte NOOFDB                        =  (byte) 4;
    final static byte PINLEN                       = (byte) 16;
    
    final static byte KEY_SIZE                      = (byte) 32;

   private   byte           NumKey = 0;
   private   byte           DBID = 0; 
   private   RandomData     m_secureRandom = null;
   private   MessageDigest  m_hash = null;
   private   AESKey         m_aesLongKey = null;
   private   Cipher         m_encryptCipher = null;
   private   Cipher         m_decryptCipher = null;
   
   private   AESKey         m_aesSessionKey = null;
   private   Cipher         m_encryptSKCipher = null;
   private   Cipher         m_decryptSKCipher = null;
   
   private byte[] LongKey = new byte[16];
   private byte[] SessionKey = new byte[16];
   private byte AdminPin[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, 0x3D};
   byte[]    N_B = new byte[16];
   byte[]    resN_1 = new byte[16];

  

    private   AESKey[]         KeyArray = new AESKey[NOOFDB];
    //private   AESKey[]         IVArray = new AESKey[NOOFDB];
    private   OwnerPIN[]       PINArray = new OwnerPIN[NOOFDB];

    /**
     * SimpleApplet default constructor
     * Only this class's install method should create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length)
    {
        
        // CREATE RANDOM DATA GENERATORS
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM); 

            // INIT HASH ENGINE
            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            
            // CREATE AES KEY OBJECT
            m_aesLongKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            
            // CREATE AES KEY OBJECT
            m_aesSessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptSKCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            m_decryptSKCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            	   
            for(short i=0; i<NOOFDB; i++) 
 	    {
		PINArray[i] = new OwnerPIN((byte) 3, PINLEN);
	    }

            for(short i=0; i<NOOFDB; i++) 
            {
                KeyArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            }
	    /*for(short i=0; i<NOOFDB; i++) {
                IVArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
                }*/
            
            register();
        
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        /*short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;          


	    // CREATE RANDOM DATA GENERATORS
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);             
	   
            for(short i=0; i<DB_CNT; i++) 
 	    {
		PINArray[i] = new OwnerPIN((byte) 3, PIN_LEN);
	    }

            for(short i=0; i<DB_CNT; i++) KeyArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
	    for(short i=0; i<DB_CNT; i++) IVArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);

            isOP2 = true;

        } else {
           // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
           // if(length != <PUT YOUR PARAMETERS LENGTH> )
           //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + length));
       }

        // <PUT YOUR CREATION ACTION HERE>

        // register this instance
          register();*/
    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new SimpleApplet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {

        // <PUT YOUR DESELECTION ACTION HERE>

        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();        

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        try {            
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                switch ( apduBuffer[ISO7816.OFFSET_INS] )
                {
                    case INS_GENKEY: GenKey(apdu); break;     
                    case INS_SETKEY: SetKey(apdu); break;                    
		    case INS_GETKEY: GetKey(apdu); break; 
                    case INS_N_1: GetN_1(apdu); break; 
                    case INS_N_B: GetN_B(apdu); break; 
                    default :
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                    break ;
                }
            }
            else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
            
            // Capture all reasonable exceptions and change into readable ones (instead of 0x6f00) 
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
        
    }
    
    
    /*void GenKey(APDU apdu)
    {
        byte[]    apdubuf = apdu.getBuffer();
        byte[]    Temp = new byte[20];
        byte[]    res = new byte[16];
        short     dataLen = apdu.setIncomingAndReceive();
        
        
        Util.arrayCopyNonAtomic(AdminPin, (short) 0, Temp, (short) 0,  (short) AdminPin.length);
        Util.arrayCopyNonAtomic(apdubuf, (short) 0, Temp, (short) 0,  (short) AdminPin.length);
        
        
        //Doing HASH
        //Calculating the HASH on above buffer
        if (m_hash != null) {
            m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, Temp, (short) 0);
            
            for(short i = 0; i < 1000; i++)
            {
                m_hash.doFinal(Temp, (short) 0, (short) Temp.length, Temp, (short) 0);
            }
            
            m_hash.doFinal(Temp, (short) 0, (short) Temp.length, Temp, (short) 0);
            
        }
        
        Util.arrayCopyNonAtomic(Temp, (short) 0, LongKey, (short) 0,  (short) 16);

        // SET KEY VALUE
            m_aesLongKey.setKey(LongKey, (short) 0);

            // INIT CIPHERS WITH NEW KEY
            m_encryptCipher.init(m_aesLongKey, Cipher.MODE_ENCRYPT);
            
            //byte[] ptdata = "123456789abcdefg".getBytes();

            //m_encryptCipher.doFinal(ptdata, (short) 0, (short) 16, res, (short) 0);
            
        
            //System.out.println(res);
    }*/
    
    void GenKey(APDU apdu)
    {
        byte[]    apdubuf = apdu.getBuffer();
        byte[]    Temp = new byte[20];
        byte[]    res = new byte[16];
        short     dataLen = apdu.setIncomingAndReceive();
        
        //Doing HASH
        //Calculating the HASH on above buffer
        if (m_hash != null) {
            m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, Temp, (short) 0);
            
            for(short i = 0; i < 1000; i++)
            {
                m_hash.doFinal(Temp, (short) 0, (short) Temp.length, Temp, (short) 0);
            }
            
            m_hash.doFinal(Temp, (short) 0, (short) Temp.length, Temp, (short) 0);
            
        }
        
        Util.arrayCopyNonAtomic(Temp, (short) 0, LongKey, (short) 0,  (short) 16);

        // SET KEY VALUE
            m_aesLongKey.setKey(LongKey, (short) 0);

            // INIT CIPHERS WITH NEW KEY
            m_encryptCipher.init(m_aesLongKey, Cipher.MODE_ENCRYPT);
            
            //byte[] ptdata = "123456789abcdefg".getBytes();

            //m_encryptCipher.doFinal(ptdata, (short) 0, (short) 16, res, (short) 0);
            
        
            //System.out.println(res);
    }
    
    void GetN_1(APDU apdu)
    {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        byte[]    res = new byte[32];
        byte[]    Temp = new byte[48];
        
        m_decryptCipher.init(m_aesLongKey, Cipher.MODE_DECRYPT);
        
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, res, (short) 0);
        
        Util.arrayCopyNonAtomic(res, (short) 0, resN_1, (short) (0), (short) 16);
        
        
        m_secureRandom.generateData(N_B, (byte)0, (byte) (16));

        Util.arrayCopyNonAtomic(resN_1, (short) 0, Temp, (short) (0), (short) 16);
        Util.arrayCopyNonAtomic(N_B, (short) 0, Temp, (short) (16), (short)N_B.length);
        for(short i=(short)(2*16);i<(short)(3*16);i++) Temp[i] = (byte) 0x42;
        //Util.arrayCopyNonAtomic("BBBBBBBBBBBBBBBB".getBytes(), (short) 0, Temp, (short) (16+16), (short)16);
        
        m_encryptCipher.init(m_aesLongKey, Cipher.MODE_ENCRYPT);

        m_encryptCipher.doFinal(Temp, (short) 0, (short) 48, apdubuf, (short) ISO7816.OFFSET_CDATA);
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)48);        
    }
    
    void GetN_B(APDU apdu)
    {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        byte[]    resN_B = new byte[dataLen];
        byte[]    Temp = new byte[32];
        byte[]    Temp1 = new byte[20];
        
        m_decryptCipher.init(m_aesLongKey, Cipher.MODE_DECRYPT);
        
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, resN_B, (short) 0);
        
        short i = Util.arrayCompare(N_B, (short)0, resN_B, (short)0, dataLen);
        
        if(i == 0)
        {
            Util.arrayCopyNonAtomic(resN_1, (short) 0, Temp, (short) (0), (short) 16);
            Util.arrayCopyNonAtomic(N_B, (short) 0, Temp, (short) (16), (short)16);  
         
            //Calculating the HASH
            if (m_hash != null) {
                m_hash.doFinal(Temp, (short) 0, (short) Temp.length, Temp1, (short) 0);
                Util.arrayCopyNonAtomic(Temp1, (short) 0, SessionKey, (short) 0,  (short) 16);
            }
        }
        else
        {
            ISOException.throwIt(SW_WRONG_N_B);
        }
    }

    // SET the KEY
    void SetKey(APDU apdu) 
    {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      byte[]    RandomNumber = new byte[2*KEY_SIZE];
      m_secureRandom.generateData(RandomNumber, (byte)0, (byte) (2*KEY_SIZE));
      
      /*// SET KEY VALUE
      m_aesSessionKey.setKey(SessionKey, (short) 0);

      // INIT CIPHERS WITH NEW KEY
      m_encryptSKCipher.init(m_aesSessionKey, Cipher.MODE_ENCRYPT);
            
      m_encryptSKCipher.doFinal(RandomNumber, (short) 0, (short) (2*KEY_SIZE), RandomNumber, (short) 0);      
      */
      KeyArray[NumKey].setKey(RandomNumber, (byte)0);  
      //IVArray[NumKey].setKey(RandomNumber, KEY_SIZE);   
      PINArray[NumKey].update(apdubuf,ISO7816.OFFSET_CDATA, (byte)dataLen);
      NumKey++;
      //Handle
      apdubuf[ISO7816.OFFSET_CDATA] = (byte)(NumKey-1);
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)1);
    }

    void GetKey(APDU apdu) 
    {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      byte[]    Temp = new byte[64];
      short FlagMatch = 1;
      
      byte Handle = apdubuf[ISO7816.OFFSET_CDATA];
      
      if(Handle < NumKey)
      {
        if (PINArray[Handle].check(apdubuf, (byte)(ISO7816.OFFSET_CDATA+1), (byte) (dataLen-1)) == true)
        {
            FlagMatch = 1;                  
        }
        else 
        {
            FlagMatch = 0;
            ISOException.throwIt(SW_BAD_PIN);
        }
      }
      else ISOException.throwIt(SW_BAD_Handle);
      
      if(FlagMatch==1) 
      {
              //DBID = (byte)j;
              apdubuf[ISO7816.OFFSET_CDATA] = Handle;
              KeyArray[Handle].getKey(Temp, (byte)0);
              
              //IVArray[Handle].getKey(Temp, (byte)32);
              
              // SET KEY VALUE
              m_aesSessionKey.setKey(SessionKey, (short) 0);

              // INIT CIPHERS WITH NEW KEY
              m_encryptSKCipher.init(m_aesSessionKey, Cipher.MODE_ENCRYPT);
            
              //m_encryptSKCipher.doFinal(Temp, (short) 0, (short) (2*KEY_SIZE), Temp, (short) 0);      
              m_encryptSKCipher.doFinal(Temp, (short) 0, (short) (KEY_SIZE), Temp, (short) 0);      
              
              Util.arrayCopyNonAtomic(Temp, (short) 0, apdubuf, (short) (ISO7816.OFFSET_CDATA + 1), (short) (KEY_SIZE) );

              apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)(1+KEY_SIZE));
              
              return;
      }
    } 
}