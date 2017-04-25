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

/**
 *
 * @author globe
 */
public class PCSideCardInterface {
    
    static CardMngr cardMngr = new CardMngr();
    
    private static byte APPLET_AID[] = {
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    public final static byte EMPTY[] = {};
    
    public final static byte SEND_INS_GETKEY[]                = {(byte) 0xB0, (byte) 0x53};
    public final static byte SEND_INS_SETKEY[]                = {(byte) 0xB0, (byte) 0x52};
    
    final static short OK                               = (short) 0x9000;
    final static short SW_BAD_PIN                       = (short) 0x6900;
    
    public PCSideCardInterface() {
        // Init card simulator
        // byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial PIN, PUK etc.
        cardMngr.prepareLocalSimulatorApplet(APPLET_AID, EMPTY, SimpleApplet.class);
    
        // Init real card
        // TODO real card
        
    }
    
    //Method used to construct APDU with instruction and optional additional data, send it and receive response
    //public byte[] sendApduAndReceive(byte[] instruction, byte P1, byte P2, byte[] additionalData)  {
    public byte[] sendApduAndReceive(byte[] instruction, byte P1, byte P2,byte[] additionalData) {
        
        short additionalDataLen = (short) additionalData.length;
        byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];

        System.arraycopy(instruction, 0, apdu, 0, 2);
        apdu[CardMngr.OFFSET_P1]=P1;
        apdu[CardMngr.OFFSET_P2]=P2;
        apdu[CardMngr.OFFSET_LC]=(byte) additionalDataLen;
        if(additionalDataLen>0)
            System.arraycopy(additionalData,0,apdu, CardMngr.OFFSET_DATA,additionalDataLen);
        try {
            // TODO real card
            // TODO parse correct answers and error
            byte[] response = cardMngr.sendAPDUSimulator(apdu);
          
            return response;

        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
        return null;
    } 
    
    private boolean parseStatusWord(byte[] status, int arraylength) throws InvalidPasswordException{
        if(arraylength!=2) return false;
        
//        short[] shortstatus=new short[2];
//        for (int i=0;i<2;i++) shortstatus[i]=(short)(status[i]& 0xff);
//        System.out.println(0x100 * shortstatus[0] + shortstatus[1]);
//      switch((short)(0x100 * shortstatus[0] + shortstatus[1])){
////        switch((short)i){
//            case OK: return true; break;
//            case SW_BAD_PIN: throw new SmartUPMAppletException ("PIN was not accepted."); break;
//            default: throw new SmartUPMAppletException ("Unexpected response from applet."); break;
//        }
        
        short shortstatus= (short) ((short)0x100 * (short)(status[0]& 0xff) + (short)(status[1]& 0xff));
        if(shortstatus==OK){
            return true;
        }
        else if (shortstatus==SW_BAD_PIN){
            throw new InvalidPasswordException();
        }
        else throw new InvalidPasswordException();
    }
    
    public byte[] sendAppletInstruction(byte[] instruction, byte P1, byte P2, byte[] Handle, char[] password) throws InvalidPasswordException{
    
    byte[] databasePinBytes = new String(password).getBytes(Charset.forName("UTF-8"));
    byte[] additionalData = new byte[1+databasePinBytes.length];
    
    if(Handle == null)
    {
        additionalData = databasePinBytes;
    }
    else
    {        
        //additionalData = Util.mergeArrays(Handle,databasePinBytes);      
        additionalData[0] = (byte) Handle[0];
        for(short i=0;i<databasePinBytes.length;i++)
            additionalData[i+1] = databasePinBytes[i];
    }
        
        try{
            byte[] result=null;
            byte[] response=sendApduAndReceive(instruction, P1, P2, additionalData);

            //if(response.length<2) throw new SmartUPMAppletException("Unexpected Applet Response.");

            //Applet response is at least 2 bytes, last 2 bytes are status word.

            if(response.length>2){
                result=new byte[response.length-2];
                System.arraycopy(response,0,result,0,result.length);
            }
            byte status[]=new byte[2];
            System.arraycopy(response,response.length-2,status,0,2);
            
            if (parseStatusWord(status, status.length)) return result;
            else return null;
            
            /*if( (status[0] == 0x90) && (status[1] == 0x0) )
                return result;
            else return null; */           
        }
        catch(Exception ex){
            throw ex;
        }
    }
}