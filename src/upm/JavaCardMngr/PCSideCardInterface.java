/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package upm.JavaCardMngr;

import JavaCardApplet.SimpleApplet;
import com._17od.upm.crypto.InvalidPasswordException;
import com._17od.upm.util.Util;
import java.nio.charset.Charset;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author globe
 */
public class PCSideCardInterface {
    
    static CardMngr cardMngr = new CardMngr();
    
    private static byte APPLET_AID[] = {
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private static byte SELECT_SIMPLEAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C,
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    public final static byte EMPTY[] = {};
    
    public final static byte SEND_INS_GETKEY[]                = {(byte) 0xB0, (byte) 0x53};
    public final static byte SEND_INS_SETKEY[]                = {(byte) 0xB0, (byte) 0x52};
    public final static byte SEND_INS_GENKEY[]                = {(byte) 0xB0, (byte) 0x50};
    public final static byte SEND_INS_N_1[]                = {(byte) 0xB0, (byte) 0x51};
    public final static byte SEND_INS_N_B[]                = {(byte) 0xB0, (byte) 0x54};
    
    final static short OK                               = (short) 0x9000;   
    
    public static final int FileHandle_LENGTH = 1;
    
    public PCSideCardInterface() throws Exception {
        
        // Init real card 
        try{                
            if (cardMngr.ConnectToCard())//Real Card
            {
                        // Select our application on card
                         cardMngr.sendAPDU(SELECT_SIMPLEAPPLET);//Real Card
            }
        }
        catch (Exception ex)
        {
            System.out.println("Exception : " + ex);
        }
        
        // Init card simulator
        //cardMngr.prepareLocalSimulatorApplet(APPLET_AID, EMPTY, SimpleApplet.class);
    }    
    
    //Send and Receive APDU
    public byte[] SendandReceiveApdu(byte[] instruction, byte P1, byte P2,byte[] additionalData) {
        
        short additionalDataLen = (short) additionalData.length;
        byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];

        System.arraycopy(instruction, 0, apdu, 0, 2);
        apdu[CardMngr.OFFSET_P1]=P1;
        apdu[CardMngr.OFFSET_P2]=P2;
        apdu[CardMngr.OFFSET_LC]=(byte) additionalDataLen;
        if(additionalDataLen>0)
            System.arraycopy(additionalData,0,apdu, CardMngr.OFFSET_DATA,additionalDataLen);
        try {
            
            // Init card simulator
            /*byte[] response = cardMngr.sendAPDUSimulator(apdu);          
            return response;*/
            
            //For Real Card
            ResponseAPDU output = cardMngr.sendAPDU(apdu);//Real Card
            byte[] ResponseText = output.getBytes();
            return ResponseText;

        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
        return null;
    } 
    
    //Parsing the Status received from Card
    private boolean ParseStatus(byte[] response, int responselength) throws InvalidPasswordException{
        
        //Card response length has to be 2
        if(responselength == 2)
        {
            short shortstatus= (short) ((short)0x100 * (short)(response[0]& 0xff) + (short)(response[1]& 0xff));
            if(shortstatus==OK)
            {
                return true;
            }        
            else throw new InvalidPasswordException();
        }
        else return false;
    }
    
    //SendAppletIns for Secure Channel
    public byte[] SendAppletInstructionSecureChannel (byte[] instruction, byte P1, byte P2, byte[] data) throws Exception
    {
        byte[] additionalData = new byte[data.length];
    
        System.arraycopy(data, 0, additionalData, 0, data.length);
        
        try{
            byte[] result=null;
            byte[] response=SendandReceiveApdu(instruction, P1, P2, additionalData);   
            
            //The response has to be atleast 2 bytes long
            if(response.length > 2)
            {
                result=new byte[response.length-2];
                System.arraycopy(response,0,result,0,result.length);
            }
            else
            {
                result=new byte[response.length];
                System.arraycopy(response,0,result,0,result.length);
            }
            
            byte status[]=new byte[2];
            System.arraycopy(response,response.length-2,status,0,2);
            
            if (ParseStatus(status, status.length)) return result;
            else return null;
        }
        catch(Exception ex){
            throw ex;
        }
    }    
    
    //SendApplet Instruction 
    public byte[] SendAppletInstruction(byte[] instruction, byte P1, byte P2, byte[] Handle, char[] password) throws InvalidPasswordException{
    
    byte[] databasePinBytes = new String(password).getBytes(Charset.forName("UTF-8"));
    byte[] additionalData = new byte[FileHandle_LENGTH + databasePinBytes.length];
    
    //For new database
    if(Handle == null)
    {
        additionalData = databasePinBytes;
    }   
    else //for opening existing database
    {   
        additionalData[0] = (byte) Handle[0];
        for(short i=0;i<databasePinBytes.length;i++)
            additionalData[i+1] = databasePinBytes[i];
    }
        
    try{
            byte[] result=null;
            byte[] response=SendandReceiveApdu(instruction, P1, P2, additionalData);
        
            //The response has to be atleast 2 bytes long
            if(response.length > 2)
            {
                result=new byte[response.length-2];
                System.arraycopy(response,0,result,0,result.length);
            }
            byte status[]=new byte[2];
            System.arraycopy(response,response.length-2,status,0,2);
            
            if (ParseStatus(status, status.length)) return result;
            else return null;
        }
        catch(Exception ex){
            throw ex;
        }
    }
}