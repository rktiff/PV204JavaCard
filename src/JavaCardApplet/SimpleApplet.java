package JavaCardApplet;

// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SimpleApplet extends javacard.framework.Applet
{
   // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET                = (byte) 0xB0;

    // INSTRUCTIONS
   
    final static byte INS_SETKEY                     = (byte) 0x52;   
    final static byte INS_GETKEY                     = (byte) 0x53;
   

    final static byte PIN_LEN                       = (byte) 16;
    final static byte DB_CNT                        =  (byte) 4;
    final static byte IV_SIZE                       = (byte) 16;
    final static byte KEY_SIZE                      = (byte) 32;
    
    //final static short ARRAY_LENGTH                   = (short) 0xff;
    //final static byte  AES_BLOCK_LENGTH               = (short) 0x16;

    
    final static short SW_BAD_Handle             = (short) 0x6715;
   
    final static short SW_BAD_PIN                    = (short) 0x6900;
    
    private   AESKey[]         KeyArray = new AESKey[DB_CNT];
    private   AESKey[]         IVArray = new AESKey[DB_CNT];
    private   OwnerPIN[]       PINArray = new OwnerPIN[DB_CNT];
    
    private   byte           NumKey = 0;
    private   byte           DBID = 0;
    private   RandomData     m_secureRandom = null;
        
    protected SimpleApplet(byte[] buffer, short offset, byte length)
    {
        m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        
        for(short i=0; i<DB_CNT; i++) PINArray[i] = new OwnerPIN((byte) 3, (byte) PIN_LEN);
        for(short i=0; i<DB_CNT; i++) KeyArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        for(short i=0; i<DB_CNT; i++) IVArray[i] = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        register();
        /*// data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
           
            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            
            // CREATE RANDOM DATA GENERATORS
             m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 0);      
            
            // update flag
            isOP2 = true;

        } 
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
        if (selectingApplet())
            return;

        try {
            
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                switch ( apduBuffer[ISO7816.OFFSET_INS] )
                {
                    case INS_SETKEY: SetKey(apdu); break;                  
                    case INS_GETKEY: GetKey(apdu); break;                    
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
        }    
    }
    
    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      byte[]    RandomNumber = new byte[2*KEY_SIZE];
      m_secureRandom.generateData(RandomNumber, (byte)0, (byte) (2*KEY_SIZE));
      

      KeyArray[NumKey].setKey(RandomNumber, (byte)0);  
      IVArray[NumKey].setKey(RandomNumber, (byte)KEY_SIZE);   
      PINArray[NumKey].update(apdubuf,ISO7816.OFFSET_CDATA, (byte)dataLen);
      NumKey++;
      //Handle
      apdubuf[ISO7816.OFFSET_CDATA] = (byte)(NumKey-1);
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)1);
    }   

    void GetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      byte[]    Temp = new byte[32];
      short FlagMatch = 1;
      
      byte Handle = (byte) apdubuf[ISO7816.OFFSET_CDATA];
      
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
              apdubuf[ISO7816.OFFSET_CDATA] = (byte)Handle;
              KeyArray[Handle].getKey(Temp, (byte)0);
              for(short i=0; i<KEY_SIZE; i++)
                apdubuf[i+ISO7816.OFFSET_CDATA+1] = Temp[i];
              IVArray[Handle].getKey(Temp, (byte)0);
              for(short i=0; i<IV_SIZE; i++)
                apdubuf[i+ISO7816.OFFSET_CDATA+33] = Temp[i];              
              apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)(1+KEY_SIZE+IV_SIZE));
              return;
      }
    }    
}
