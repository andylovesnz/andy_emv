//Peter Fillmore - 2014
//
//--------------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
//Routines to support EMV transactions
//--------------------------------------------------------------------------------

#include "mifare.h"
#include "iso14443a.h"
#include "emvutil.h"
#include "emvcmd.h"
#include "apps.h"
#include "emvdataels.h"

//global emvcard struct
static emvcard currentcard;
//static tUart Uart;
//static tDemod Demod;

/*
void EMVTest()
{
    //iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    uint8_t data[] = {0x6F,0x43,0x84,0x07,0xA0,0x00,0x00,0x00,0x03,0x10,0x10,0xA5,0x38,0x50,0x0C,0x56,0x69,0x73,0x61,0x20,0x50,0x72,0x65,0x70,0x61,0x69,0x64,0x87,0x01,0x01,0x9F,0x38,0x0C,0x9F,0x66,0x04,0x9F,0x02,0x06,0x9F,0x37,0x04,0x5F,0x2A,0x02,0x5F,0x2D,0x02,0x65,0x6E,0x9F,0x11,0x01,0x01,0x9F,0x12,0x0C,0x50,0x6F,0x73,0x74,0x20,0x50,0x72,0x65,0x70,0x61,0x69,0x64,0x90,0x00};
    EMVFuzz_PPSE(sizeof(data), data); 
    //EmSendCmdChain(data, 71, 64); 
    //clonedcard newcard;
    //EMVQuickClone(&newcard);
}

void EMVCloneCard()
{
    LED_C_OFF();   
    if(!EMVClone(5,5)){ //5,5 
        if(EMV_DBGLEVEL >= 1) Dbprintf("Can't select card");
        return; 
    }
    LED_C_ON(); // card has been loaded
    //now lets SIM
    LED_B_ON();
    EMVSim();
}
*/
void EMVReadRecord(uint8_t arg0, uint8_t arg1,emvcard *currentcard)
{
    uint8_t record = arg0;
    uint8_t sfi = arg1 & 0x0F; //convert arg1 to number
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
   
     //uint8_t receivedAnswerPar[MAX_PARITY_SIZE];
    
    //variables
    tlvtag inputtag; //create the tag structure
    //perform read 
    //write the result to the provided card 
    if(!emv_readrecord(record,sfi,receivedAnswer)) {
        if(EMV_DBGLEVEL >= 1) Dbprintf("readrecord failed");
    }
    if(*(receivedAnswer+1) == 0x70){ 
        decode_ber_tlv_item(receivedAnswer+1, &inputtag);
        emv_decode_field(inputtag.value, inputtag.valuelength, currentcard); 
    } 
    else
    {
        if(EMV_DBGLEVEL >= 1) 
            Dbprintf("Record not found SFI=%i RECORD=%i", sfi, record); 
    }
    return;
}

void EMVSelectAID(uint8_t *AID, uint8_t AIDlen, emvcard* inputcard)
{
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
    //uint8_t receivedAnswerPar[MAX_PARITY_SIZE];
    
    //variables
    tlvtag inputtag; //create the tag structure
    //perform select 
    if(!emv_select(AID, AIDlen, receivedAnswer)){
        if(EMV_DBGLEVEL >= 1) Dbprintf("AID Select failed");
        return; 
    }
    //write the result to the provided card 
    if(*(receivedAnswer+1) == 0x6F){ 
        //decode the 6F template 
        decode_ber_tlv_item(receivedAnswer+1, &inputtag);
        //store 84 and A5 tags 
        emv_decode_field(inputtag.value, inputtag.valuelength, &currentcard); 
        //decode the A5 tag 
        if(currentcard.tag_A5_len > 0) 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
        
        //copy this result to the DFName 
        if(currentcard.tag_84_len == 0) 
            memcpy(currentcard.tag_DFName, currentcard.tag_84, currentcard.tag_84_len);
        
        //decode the BF0C result, assuming 1 directory entry for now 
        if(currentcard.tag_BF0C_len !=0){
            emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
         //retrieve the AID, use the AID to decide what transaction flow to use 
        if(currentcard.tag_61_len !=0){
                emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);}
    }
    if(EMV_DBGLEVEL >= 2) 
        DbpString("SELECT AID COMPLETED");
}

int EMVGetProcessingOptions(uint8_t *PDOL, uint8_t PDOLlen, emvcard* inputcard)
{
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
    //uint8_t receivedAnswerPar[MAX_PARITY_SIZE];
     
    //variables
    tlvtag inputtag; //create the tag structure
    //perform select 
    if(!emv_getprocessingoptions(PDOL, PDOLlen, receivedAnswer)){
        if(EMV_DBGLEVEL >= 1) Dbprintf("get processing options failed");
        return 1; 
    }
    //write the result to the provided card 
    //FORMAT 1 received 
    if(receivedAnswer[1] == 0x80){ 
        //store AIP
        //decode tag 80 
        decode_ber_tlv_item(receivedAnswer+1, &inputtag);
        memcpy(currentcard.tag_82, &inputtag.value, sizeof(currentcard.tag_82));
        memcpy(currentcard.tag_94, &inputtag.value[2], inputtag.valuelength - sizeof(currentcard.tag_82));
        currentcard.tag_94_len = inputtag.valuelength - sizeof(currentcard.tag_82); 
    }
    else if(receivedAnswer[1] == 0x77){
        //decode the 77 template 
        decode_ber_tlv_item(receivedAnswer+2, &inputtag);
        //store 82 and 94 tags (AIP, AFL) 
        emv_decode_field(inputtag.value, inputtag.valuelength, &currentcard); 
    } 
    if(EMV_DBGLEVEL >= 2) 
        DbpString("GET PROCESSING OPTIONS COMPLETE");
    return 0;
}

int EMVGetChallenge(emvcard* inputcard)
{
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
    //uint8_t receivedAnswerPar[MAX_PARITY_SIZE];
    
    //variables
    //tlvtag inputtag; //create the tag structure
    //perform select 
    if(!emv_getchallenge(receivedAnswer)){
        if(EMV_DBGLEVEL >= 1) Dbprintf("get processing options failed");
        return 1; 
    }
    //TODO complete function 
    return 0;
}

int EMVGenerateAC(uint8_t refcontrol, emvcard* inputcard)
{
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
    uint8_t cdolcommand[MAX_FRAME_SIZE];
    uint8_t cdolcommandlen = 0;
    tlvtag temptag;
 
    //uint8_t receivedAnswerPar[MAX_PARITY_SIZE];
    if(currentcard.tag_8C_len > 0) { 
        emv_generateDOL(currentcard.tag_8C, currentcard.tag_8C_len, &currentcard, cdolcommand, &cdolcommandlen); }
    else{
            //cdolcommand = NULL; //cdol val is null
        cdolcommandlen = 0;
    }
    //variables
    //tlvtag inputtag; //create the tag structure
    //perform select 
    if(!emv_generateAC(refcontrol, cdolcommand, cdolcommandlen,receivedAnswer)){
        if(EMV_DBGLEVEL >= 1) Dbprintf("get processing options failed");
        return 1; 
    }
    if(receivedAnswer[2] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&receivedAnswer[2], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
    
    return 0;
}
//int EMV_PaywaveTransaction()
//{
//    //uint8_t *responsebuffer  = emv_get_bigbufptr(); 
//    tlvtag temptag; //buffer for decoded tags 
//    //get the current block counter 
//    //select the AID (Mastercard 
//    Dbprintf("SELECTING AID..."); 
//    Dbprintf("AIDlen=%u", currentcard.tag_4F_len); 
//    Dbhexdump(currentcard.tag_4F_len, currentcard.tag_4F, false); 
//    EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
//    //Dbhexdump(100,responsebuffer,false); 
//    
//    //get PDOL
//    uint8_t pdolcommand[20]; //20 byte buffer for pdol data 
//    uint8_t pdolcommandlen = 0; 
//    if(currentcard.tag_9F38_len > 0) { 
//        emv_generateDOL(currentcard.tag_9F38, currentcard.tag_9F38_len, &currentcard, pdolcommand, &pdolcommandlen); 
//    }
//    else{
//        //pdolcommand = NULL; //pdol val is null
//        pdolcommandlen = 0;
//    }
//    if(!emv_getprocessingoptions(pdolcommand,pdolcommandlen)) {
//        if(EMV_DBGLEVEL >= 1) Dbprintf("PDOL failed");
//        return 1; 
//    }
//    if(responsebuffer[1] == 0x80) //format 1 data field returned
//    { 
//        memcpy(currentcard.tag_82, &responsebuffer[3],2); //copy AIP
//        currentcard.tag_94_len =  responsebuffer[2]-2; //AFL len
//        memcpy(currentcard.tag_94, &responsebuffer[5],currentcard.tag_94_len); //copy AFL 
//    }
//    else if(responsebuffer[1] == 0x77) //format 2 data field returned
//    {
//        decode_ber_tlv_item(&responsebuffer[1], &temptag);
//        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
//    } 
//    else
//    {
//        //throw an error
//    }
//    Dbprintf("AFL=");
//    Dbhexdump(currentcard.tag_94_len, currentcard.tag_94,false); 
//    Dbprintf("AIP=");
//    Dbhexdump(2, currentcard.tag_82, false); 
//    emv_decodeAIP(currentcard.tag_82); 
//    
//    //decode the AFL list and read records 
//       
//    //record, sfi 
//    EMVReadRecord( 1,1, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 2,1, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 1,2, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 2,2, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 3,2, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 4,2, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 1,3, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 2,3, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    EMVReadRecord( 4,2, &currentcard);
//    EMVReadRecord( 1,3, &currentcard);
//    Dbhexdump(200, responsebuffer,false); 
//    //EMVReadRecord( 2,3, &currentcard);
//    //Dbhexdump(200, responsebuffer,false); 
//    
//    //DDA supported, so read more records 
//    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED){ 
//        EMVReadRecord( 1,4, &currentcard);
//        EMVReadRecord( 2,4, &currentcard);
//    }
//
//     
//   emv_decodeCVM(currentcard.tag_8E, currentcard.tag_8E_len); 
//    /* get ICC dynamic data */
//    //if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
//    {
//        //DDA supported, so perform GENERATE AC 
//        uint8_t cdolcommand[40]; //20 byte buffer for pdol data 
//        uint8_t cdolcommandlen; 
//        //generate the iCC UN 
//        emv_getchallenge();
//        memcpy(currentcard.tag_9F37,&responsebuffer[1],8); // ICC UN 
//        memcpy(currentcard.tag_9F4C,&responsebuffer[1],8); // ICC UN 
//        if(currentcard.tag_8C_len > 0) { 
//            emv_generateDOL(currentcard.tag_8C, currentcard.tag_8C_len, &currentcard, cdolcommand, &cdolcommandlen); }
//        else{
//            //cdolcommand = NULL; //cdol val is null
//            cdolcommandlen = 0;
//        }
//        Dbhexdump(currentcard.tag_8C_len, currentcard.tag_8C,false); 
//        Dbhexdump(cdolcommandlen, cdolcommand,false); 
//        emv_generateAC(0x41, cdolcommand,cdolcommandlen);
//         
//        Dbhexdump(100, responsebuffer,false); 
//        //Dbhexdump(200, responsebuffer,false); 
//       /* 
//        if(responsebuffer[1] == 0x77) //format 2 data field returned
//        {
//            decode_ber_tlv_item(&responsebuffer[1], &temptag);
//            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
//        }
//        //generate AC2  
//        if(currentcard.tag_8D_len > 0) { 
//            emv_generateDOL(currentcard.tag_8D, currentcard.tag_8D_len, &currentcard, cdolcommand, &cdolcommandlen); }
//        else{
//            //cdolcommand = NULL; //cdol val is null
//            cdolcommandlen = 0;
//        }
//        emv_generateAC(0x80, cdolcommand,cdolcommandlen);
//        
//        if(responsebuffer[1] == 0x77) //format 2 data field returned
//        {
//            decode_ber_tlv_item(&responsebuffer[1], &temptag);
//            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
//        }
//    } 
//    //generate cryptographic checksum
//    uint8_t udol[4] = {0x00,0x00,0x00,0x00}; 
//    emv_computecryptogram(udol, sizeof(udol));
//    if(responsebuffer[1] == 0x77) //format 2 data field returned
//    {
//        decode_ber_tlv_item(&responsebuffer[1], &temptag);
//        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); */ 
//    } 
//return 0;    
//} 


int EMV_PaypassTransaction()
{
    //uint8_t *responsebuffer  = emv_get_bigbufptr(); 
    //tlvtag temptag; //buffer for decoded tags 
    //get the current block counter 
    //select the AID (Mastercard 
    EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
    
    //if(responsebuffer[1] == 0x6F){ //decode template
    //    decode_ber_tlv_item(&responsebuffer[1], &temptag);
    //    //decode 84 and A5 tags 
    //    emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
    //    //decode the A5 tag 
    //    emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
    //    //decode the BF0C result, assuming 1 directory entry for now 
    //    //retrieve the AID 
    //}
    //get PDOL
    uint8_t pdolcommand[20]; //20 byte buffer for pdol data 
    uint8_t pdolcommandlen = 0; 
    if(currentcard.tag_9F38_len > 0) { 
        emv_generateDOL(currentcard.tag_9F38, currentcard.tag_9F38_len, &currentcard, pdolcommand, &pdolcommandlen); 
    }
    if(EMVGetProcessingOptions(pdolcommand,pdolcommandlen, &currentcard)) {
        if(EMV_DBGLEVEL >= 1) Dbprintf("PDOL failed");
        return 1; 
    }
    if(tracing){
            LogReceiveTrace();
    }
    //if(responsebuffer[1] == 0x80) //format 1 data field returned
    //{ 
    //    memcpy(currentcard.tag_82, &responsebuffer[3],2); //copy AIP
    //    currentcard.tag_94_len =  responsebuffer[2]-2; //AFL len
    //    memcpy(currentcard.tag_94, &responsebuffer[5],currentcard.tag_94_len); //copy AFL 
    //}
    //else if(responsebuffer[1] == 0x77) //format 2 data field returned
    //{
    //    decode_ber_tlv_item(&responsebuffer[1], &temptag);
    //    emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    //} 
    //else
    //{
    //    //throw an error
    //}
    Dbprintf("AFL=");
    Dbhexdump(currentcard.tag_94_len, currentcard.tag_94,false); 
    Dbprintf("AIP=");
    Dbhexdump(2, currentcard.tag_82, false); 
    emv_decodeAIP(currentcard.tag_82); 
    
    //decode the AFL list and read records 
    /*
    uint8_t i = 0; 
    uint8_t sfi = 0;
    uint8_t recordstart = 0; 
    uint8_t recordend = 0; 
   
    while( i< currentcard.tag_94_len){
        sfi = (currentcard.tag_94[i++] & 0xF8) >> 3;
        recordstart = currentcard.tag_94[i++];
        recordend = currentcard.tag_94[i++];
        for(int j=recordstart; j<(recordend+1); j++){
        //read records 
            EMVReadRecord(blockcounter, j,sfi, &currentcard);
            emv_decodePCB(&blockcounter);
            while(responsebuffer[0] == 0xF2) {
                EMVReadRecord(blockcounter, j,sfi, &currentcard);
                emv_decodePCB(&blockcounter);
            }
        }  
        i++;
    }
    */
    //record, sfi 
    EMVReadRecord( 1,1, &currentcard);
    if(tracing){
            LogReceiveTrace();
    }
    EMVReadRecord( 1,2, &currentcard);
    if(tracing){
            LogReceiveTrace();
    }
    EMVReadRecord( 1,3, &currentcard);
    if(tracing){
            LogReceiveTrace();
    }
    EMVReadRecord( 2,3, &currentcard);
    if(tracing){
            LogReceiveTrace();
    }
    //DDA supported, so read more records 
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED){ 
        EMVReadRecord( 1,4, &currentcard);
        EMVReadRecord( 2,4, &currentcard);
    }

    /* 
    //lets read records! 
    //limit for now to 10 SFIs and 10 records each 
    
    for(uint8_t sfi=1; sfi<11;sfi++){ 
        for(uint8_t record=1; record < 11; record++){ 
            EMVReadRecord(blockcounter, record,sfi, &currentcard);
            emv_decodePCB(&blockcounter);
            while(responsebuffer[0] == 0xF2) {
                EMVReadRecord(blockcounter, record,sfi, &currentcard);
                emv_decodePCB(&blockcounter);
            }       
        }
    }
    */ 
    /* get ICC dynamic data */
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
    {
        //DDA supported, so perform GENERATE AC 
        //generate the iCC UN 
        EMVGetChallenge(&currentcard);
        //memcpy(currentcard.tag_9F4C,&responsebuffer[1],8); // ICC UN 
        EMVGenerateAC(0x80,&currentcard);
 
        
        //generate AC2  
        //if(currentcard.tag_8D_len > 0) { 
        //    emv_generateDOL(currentcard.tag_8D, currentcard.tag_8D_len, &currentcard, cdolcommand, &cdolcommandlen); }
        //else{
        //    //cdolcommand = NULL; //cdol val is null
        //    cdolcommandlen = 0;
        //}
        //emv_generateAC(0x80, cdolcommand,cdolcommandlen, &currentcard);
        
        //if(responsebuffer[1] == 0x77) //format 2 data field returned
        //{
        //    decode_ber_tlv_item(&responsebuffer[1], &temptag);
        //    emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
        //}
    } 
    //generate cryptographic checksum
    //uint8_t udol[4] = {0x00,0x00,0x00,0x00}; 
    //emv_computecryptogram(udol, sizeof(udol));
    //if(responsebuffer[1] == 0x77) //format 2 data field returned
    //{
    //    decode_ber_tlv_item(&responsebuffer[1], &temptag);
    //    emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    //} 
    return 0;
}

void EMVTransaction()
{
    //params
    //uint8_t recordNo = arg0;
    //uint8_t sfi = arg1;
    uint8_t uid[10];
    uint32_t cuid;
    //uint8_t receivedAnswer[MAX_FRAME_SIZE]; 
    //variables
    //tlvtag temptag; //used to buffer decoded tag valuesd  
   
    //setup stuff
    BigBuf_free();
    clear_trace();
    set_tracing(TRUE);
 
    memset(&currentcard, 0x00, sizeof(currentcard)); //set all to zeros 
    //memcpy(currentcard.tag_9F66,"\x20\x00\x00\x00",4);
    memcpy(currentcard.tag_9F66,"\xD7\x20\xC0\x00",4);
    //memcpy(currentcard.tag_9F66,"\xC0\x00\x00\x00",2);
    memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6); //20 dollars 
    memcpy(currentcard.tag_9F37, "\x01\x02\x03\x04", 4); //UN 
    memcpy(currentcard.tag_5F2A, "\x00\x36",2); //currency code
    //CDOL stuff 
    //memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6);
    memcpy(currentcard.tag_9F03,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(currentcard.tag_9F1A,"\x00\x36",2); //country code
    memcpy(currentcard.tag_95,"\x00\x00\x00\x00\x00",5); //TVR
    //memcpy(currentcard.tag_5F2A,"\x00\x36",2);
    memcpy(currentcard.tag_9A,"\x14\x04\x01",3); //date
    memcpy(currentcard.tag_9C,"\x00",1); //processingcode;
    memcpy(currentcard.tag_9F45, "\x00\x00", 2); //Data Authentication Code
    memset(currentcard.tag_9F4C,0x00,8); // ICC UN
    memcpy(currentcard.tag_9F35,"\x12",1);
    memcpy(currentcard.tag_9F34,"\x3F\x00\x00", 3); //CVM 
      
    //iso14a_clear_trace();
    //iso14a_set_tracing(true);
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
 
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    while(true) { 
        if(!iso14443a_select_card(uid,NULL,&cuid)) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("Can't select card");
            break;
        }
        //selectPPSE 
        EMVSelectAID((uint8_t *)DF_PSE, 14, &currentcard); //hard coded len
        //get response
        if(!memcmp(currentcard.tag_4F, AID_MASTERCARD, sizeof(AID_MASTERCARD))){
            Dbprintf("Mastercard Paypass Card Detected"); 
            EMV_PaypassTransaction();
        }
        else if(!memcmp(currentcard.tag_4F, AID_VISA, sizeof(AID_VISA))){            
            Dbprintf("VISA Paywave Card Detected"); 
            //EMV_PaywaveTransaction();
        }
        
        //output the sensitive data
        //cmd_send(CMD_ACK, 0, 0,0,responsebuffer,100); 
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("EMV TRANSACTION FINISHED");
        //finish up
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}

/*
//EMV clone a card - read up to the max SFI and max records for that SFI
bool EMVClone(uint8_t maxsfi, uint8_t maxrecord)
{
     //params
    //uint8_t recordNo = arg0;
    //uint8_t sfi = arg1;
    uint8_t uid[10];
    uint32_t cuid;
    //uint32_t selTimer = 0; 
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
 
    iso14a_card_select_t hi14a_card; //card select values
    //variables
    tlvtag temptag; //used to buffer decoded tag valuesd  
    //byte_t isOK = 0;
    //initialize the emv card structure
    //extern emvcard currentcard;
    
    memset(&currentcard, 0x00, sizeof(currentcard)); //set all to zeros 
    //memcpy(currentcard.tag_9F66,"\x20\x00\x00\x00",4);
    memcpy(currentcard.tag_9F66,"\xD7\x20\xC0\x00",4);
    //memcpy(currentcard.tag_9F66,"\xC0\x00\x00\x00",2);
    memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6); //20 dollars 
    memcpy(currentcard.tag_9F37, "\x01\x02\x03\x04", 4); //UN 
    memcpy(currentcard.tag_5F2A, "\x00\x36",2); //currency code
    //CDOL stuff 
    //memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6);
    memcpy(currentcard.tag_9F03,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(currentcard.tag_9F1A,"\x00\x36",2); //country code
    memcpy(currentcard.tag_95,"\x00\x00\x00\x00\x00",5); //TVR
    //memcpy(currentcard.tag_5F2A,"\x00\x36",2);
    memcpy(currentcard.tag_9A,"\x14\x04x01",3); //date
    memcpy(currentcard.tag_9C,"\x00",1); //processingcode;
    memcpy(currentcard.tag_9F45, "\x00\x00", 2); //Data Authentication Code
    memset(currentcard.tag_9F4C,0x00,8); // ICC UN
    memcpy(currentcard.tag_9F35,"\x12",1);
    memcpy(currentcard.tag_9F34,"\x3F\x00\x00", 3); //CVM 
      
    iso14a_clear_trace();
    //iso14a_set_tracing(true);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
     while(true) { 
        if(!iso14443a_select_card(uid,&hi14a_card,&cuid)) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("Can't select card");
            break;
        }
        //copy UID and ATQA SAK and ATS values
        memcpy(currentcard.UID, hi14a_card.uid, hi14a_card.uidlen);  
        currentcard.UID_len = hi14a_card.uidlen; 
        memcpy(currentcard.ATQA, hi14a_card.atqa, 2);
        currentcard.SAK = (uint8_t)hi14a_card.sak;
        memcpy(currentcard.ATS, hi14a_card.ats, hi14a_card.ats_len);
        currentcard.ATS_len = hi14a_card.ats_len;
 
        if(EMV_DBGLEVEL >= 1){
            Dbprintf("UID=");
            Dbhexdump(currentcard.UID_len, currentcard.UID, false);
            Dbprintf("ATQA=");
            Dbhexdump(2, currentcard.ATQA,false);
            Dbprintf("SAK=");
            Dbhexdump(1, &currentcard.SAK,false);
            Dbprintf("ATS=");
            Dbhexdump(currentcard.ATS_len, currentcard.ATS,false);
        }
        //EMVSelectPPSE
        EMVSelectAID(DF_PSE,sizeof(DF_PSE), receivedAnswer);
 
        //get response
        if(receivedAnswer[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //copy this result to the DFName 
            memcpy(currentcard.tag_DFName, currentcard.tag_84, currentcard.tag_84_len);
            currentcard.tag_DFName_len = currentcard.tag_84_len; 
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
            if(currentcard.tag_BF0C_len !=0){
                emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
            //retrieve the AID, use the AID to decide what transaction flow to use 
            if(currentcard.tag_61_len !=0){
                emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);}
        } 
        //perform AID selection 
        EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
        if(responsebuffer[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
        }
        //decode the AFL list and read records 
        
        //scan all card records 
        Dbprintf("Reading %u SFIs and %u records...", maxsfi, maxrecord); 
        for(uint8_t sfi = 1; sfi < maxsfi; sfi++){ //all possible SFI values
            for(uint8_t record = 1; record < maxrecord; record++){
                EMVReadRecord(record,sfi, &currentcard);
                Dbhexdump(100, responsebuffer,false); 
                if(responsebuffer[1] == 0x70){ 
                    Dbprintf("Record Found! SFI=%u RECORD=%u", sfi, record);
                } 
            }
        }
        Dbprintf("Reading finished"); 
        
        //output the sensitive data
        cmd_send(CMD_ACK, 0, 0,0,responsebuffer,100); 
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("EMV TRANSACTION FINISHED");
        //finish up
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return TRUE;
}
*/
//clones card by copying responses verbatim - not reconstructing a card.
/*
bool EMVQuickClone(clonedcard* card)
{
     //params
    //uint8_t recordNo = arg0;
    //uint8_t sfi = arg1;
    uint8_t uid[10];
    uint32_t cuid;
    //uint32_t selTimer = 0; 
    uint8_t *responsebuffer  = emv_get_bigbufptr(); 
    iso14a_card_select_t hi14a_card; //card select values
    //variables
    tlvtag temptag; //used to buffer decoded tag valuesd  
    //byte_t isOK = 0;
    //initialize the emv card structure
    //extern emvcard currentcard;
    
    memset(&currentcard, 0x00, sizeof(currentcard)); //set all to zeros 
    //memcpy(currentcard.tag_9F66,"\x20\x00\x00\x00",4);
    memcpy(currentcard.tag_9F66,"\xD7\x20\xC0\x00",4);
    //memcpy(currentcard.tag_9F66,"\xC0\x00\x00\x00",2);
    memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6); //20 dollars 
    memcpy(currentcard.tag_9F37, "\x01\x02\x03\x04", 4); //UN 
    memcpy(currentcard.tag_5F2A, "\x00\x36",2); //currency code
    //CDOL stuff 
    //memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6);
    memcpy(currentcard.tag_9F03,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(currentcard.tag_9F1A,"\x00\x36",2); //country code
    memcpy(currentcard.tag_95,"\x00\x00\x00\x00\x00",5); //TVR
    //memcpy(currentcard.tag_5F2A,"\x00\x36",2);
    memcpy(currentcard.tag_9A,"\x14\x04x01",3); //date
    memcpy(currentcard.tag_9C,"\x00",1); //processingcode;
    memcpy(currentcard.tag_9F45, "\x00\x00", 2); //Data Authentication Code
    memset(currentcard.tag_9F4C,0x00,8); // ICC UN
    memcpy(currentcard.tag_9F35,"\x12",1);
    memcpy(currentcard.tag_9F34,"\x3F\x00\x00", 3); //CVM 
      
    iso14a_clear_trace();
    //iso14a_set_tracing(true);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
     while(true) { 
        if(!iso14443a_select_card(uid,&hi14a_card,&cuid)) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("Can't select card");
            break;
        }
        //copy UID and ATQA SAK and ATS values
        memcpy(card->UID, hi14a_card.uid, hi14a_card.uidlen);  
        card->UID_len = hi14a_card.uidlen; 
        memcpy(card->ATQA, hi14a_card.atqa, 2);
        card->SAK = (uint8_t)hi14a_card.sak;
        memcpy(card->ATS, hi14a_card.ats, hi14a_card.ats_len);
        card->ATS_len = hi14a_card.ats_len;
 
        if(EMV_DBGLEVEL >= 1){
            Dbprintf("UID=");
            Dbhexdump(card->UID_len, card->UID, false);
            Dbprintf("ATQA=");
            Dbhexdump(2, card->ATQA,false);
            Dbprintf("SAK=");
            Dbhexdump(1, &card->SAK,false);
            Dbprintf("ATS=");
            Dbhexdump(card->ATS_len, card->ATS,false);
        }
        EMVSelectPPSE();
        //get response
        if(responsebuffer[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            memcpy(card->respSELPPSE, &responsebuffer[1], temptag.fieldlength);  
            card->respSELPPSE_len = temptag.fieldlength; 
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag to get the ADF Name (tag 4F)
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            if(currentcard.tag_BF0C_len !=0){
                emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
            //retrieve the AID, use the AID to decide what transaction flow to use 
            if(currentcard.tag_61_len !=0){
                emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);}
        } 
        //perform AID selection 
        EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
        if(responsebuffer[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            memcpy(card->respSELAID, &responsebuffer[1], temptag.fieldlength); 
            card->respSELAID_len = temptag.fieldlength;//decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
        }//assuming there are only 6 records as per the paypass specs 
        //SFI 1, REC 1 
        //get PDOL
        uint8_t pdolcommand[20]; //20 byte buffer for pdol data 
        uint8_t pdolcommandlen = 0; 
        if(currentcard.tag_9F38_len > 0) { 
            emv_generateDOL(currentcard.tag_9F38, currentcard.tag_9F38_len, &currentcard, pdolcommand, &pdolcommandlen); 
        }
        else{
            //pdolcommand = NULL; //pdol val is null
            pdolcommandlen = 0;
        }
        if(!emv_getprocessingoptions(pdolcommand,pdolcommandlen)) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("PDOL failed");
            return 1; 
        }
        if(responsebuffer[1] == 0x77){ 
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            memcpy(card->respPDOLEMV, &responsebuffer[1], temptag.fieldlength);
            card->respPDOLEMV_len = temptag.fieldlength; 
        }
        Dbhexdump(card->respPDOLEMV_len, card->respPDOLEMV, false);
 
        EMVReadRecord(1,1, &currentcard); 
        if(responsebuffer[1] == 0x70){ 
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            Dbprintf("TEMPTAGLEN=%u", temptag.fieldlength); 
            memcpy(card->respRR11, &responsebuffer[1], temptag.fieldlength);
            card->respRR11_len = temptag.fieldlength; 
             
        }
        else{
            card->respRR11_len = 0;
        } 
        //SFI 2, REC 1 
        EMVReadRecord(1,2,&currentcard) ;
        if(responsebuffer[1] == 0x70){ 
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            memcpy(card->respRR21, &responsebuffer[1], temptag.fieldlength); 
            card->respRR21_len = temptag.fieldlength; 
        }
        else{
            card->respRR21_len = 0;
        }
        
        //SFI 3, REC 1 
        if(emv_readrecord(1,3,responsebuffer)) {
            if(responsebuffer[1] == 0x70){ 
                decode_ber_tlv_item(&responsebuffer[1], &temptag);
                memcpy(card->respRR31, &responsebuffer[1], temptag.fieldlength);
                card->respRR31_len = temptag.fieldlength; 
            }
        }
        //SFI 3, REC 2    
      if(emv_readrecord(2,3,responsebuffer)) {
            if(responsebuffer[1] == 0x70){ 
                decode_ber_tlv_item(&responsebuffer[1], &temptag);
                memcpy(card->respRR32, &responsebuffer[1], temptag.fieldlength); 
                card->respRR32_len = temptag.fieldlength; 
            }
        } 
        //SFI 4, REC 1 
        if(emv_readrecord(1,4,responsebuffer)) {
            if(responsebuffer[1] == 0x70){ 
                decode_ber_tlv_item(&responsebuffer[1], &temptag);
                memcpy(card->respRR41, &responsebuffer[1], temptag.fieldlength);
                card->respRR41_len = temptag.fieldlength; 
            }
        }  //output the sensitive data
        //SFI 4 REC 2 
        if(emv_readrecord(2,4,responsebuffer)) {
            if(responsebuffer[1] == 0x70){ 
                decode_ber_tlv_item(&responsebuffer[1], &temptag);
                memcpy(card->respRR42, &responsebuffer[1], temptag.fieldlength); 
                card->respRR42_len = temptag.fieldlength;
            }
        } 
        Dbhexdump(card->respRR21_len, card->respRR21, false);

        cmd_send(CMD_ACK, 0, 0,0,responsebuffer,100); 
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("EMV TRANSACTION FINISHED");
        //finish up
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return TRUE;
}
*/
/*
//EMV simulated card - uses values in the current card structure
void EMVSim()
{
    // Enable and clear the trace
	iso14a_clear_trace();
	//iso14a_set_tracing(FALSE);
	iso14a_set_tracing(TRUE);
    UartReset();
    DemodReset();
	uint8_t sak;

	// The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t response1[2];
    
    response1[0] = currentcard.ATQA[0];
    response1[1] = currentcard.ATQA[1];
    sak = currentcard.SAK;	
	
    //setup the UID	
    uint8_t rUIDBCC1[5]; //UID 93+BCC
    uint8_t rUIDBCC2[5]; //UID 95+BCC
    uint8_t rUIDBCC3[5]; //UID 97+BCC
    
    if(currentcard.UID_len == 4){
        memcpy(rUIDBCC1, currentcard.UID,4);
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3]; 
    }
    else if(currentcard.UID_len == 7){
        rUIDBCC1[0] = 0x88; //CT
        memcpy(&rUIDBCC1[1], currentcard.UID, 3);
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3]; 
        memcpy(rUIDBCC2, &currentcard.UID[3], 4);
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3]; 
    }
    else if(currentcard.UID_len == 10){
        rUIDBCC1[0] = 0x88; //CT
        memcpy(&rUIDBCC1[1], currentcard.UID, 3);
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3]; 
        rUIDBCC2[0] = 0x88; //CT
        memcpy(&rUIDBCC2[1], &currentcard.UID[3], 3);
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        memcpy(rUIDBCC3, &currentcard.UID[6], 4);
        rUIDBCC3[4] = rUIDBCC3[0] ^ rUIDBCC3[1] ^ rUIDBCC3[2] ^ rUIDBCC3[3]; 
    }
    else{ //error - exit
       if(EMV_DBGLEVEL >= 2)
            Dbprintf("UID not set");
            return;  
    }

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t response3[3];
	response3[0] = sak;
	ComputeCrc14443(CRC_14443_A, response3, 1, &response3[1], &response3[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
	uint8_t response3a[3];
	response3a[0] = sak & 0xFB;
    ComputeCrc14443(CRC_14443_A, response3a, 1, &response3a[1], &response3a[2]);
	//ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);
    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1); 
    
    uint8_t tagvalbuffer[256];
    uint8_t tagvallen;  
    //create "Record 1 1"	
     
    //pre-generate the tag for speed.
    //Define PPSS responses (always say yes)
    uint8_t PPSS_0[] = {0xD0,0x73,0x87};
    uint8_t PPSS_1[] = {0xD1,0x00,0x00};
    AppendCrc14443a(PPSS_1, 1); 
    uint8_t DESELECT[] = {0xC2,0xE0, 0xB4};
    uint8_t F2[] = {0xf2, 0x01,0x00,0x00};
    AppendCrc14443a(F2, 2);
    uint8_t cmd0E[] = {0x0e};

    #define TAG_RESPONSE_COUNT 14 
	tag_response_info_t responses[TAG_RESPONSE_COUNT] = {
		{ .response = response1,  .response_n = sizeof(response1)  },  // Answer to request - respond with card type
		{ .response = rUIDBCC1,  .response_n = sizeof(rUIDBCC1)  },  // Anticollision cascade1 - respond with uid
		{ .response = rUIDBCC2, .response_n = sizeof(rUIDBCC2) },  // Anticollision cascade2 - respond with 2nd half of uid if asked
		{ .response = rUIDBCC3,  .response_n = sizeof(rUIDBCC3)  },  // Acknowledge select - cascade 3 - respond with 3rd part of UID 
		{ .response = response3,  .response_n = sizeof(response3)  },  // Acknowledge select - cascade 1
		{ .response = response3a, .response_n = sizeof(response3a) },  // Acknowledge select - cascade 2
		{ .response = currentcard.ATS,  .response_n = currentcard.ATS_len  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = 3}, //acknowledge packet 
		{ .response = ACK2,  .response_n = 3}, //ackknowledge packet 
        { .response = PPSS_0, .response_n = 3}, //response to protocol parameter select
        { .response = PPSS_1, .response_n = 3}, //response to pps 
        { .response = DESELECT, .response_n = 3}, //deselect
        { .response = F2, .response_n = 4}, 
        { .response = cmd0E, .response_n = 1}, 
    };

	// Allocate 512 bytes for the dynamic modulation, created when the reader queries for it
	// Such a response is less time critical, so we can prepare them on the fly
	
    // Reset the offset pointer of the free buffer
	reset_free_buffer();
  
	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
	for (size_t i=0; i<TAG_RESPONSE_COUNT; i++) {
		prepare_allocated_tag_modulation(&responses[i]);
	}
    
    //uint8_t* dynamic_response_buffer = (((uint8_t *)BigBuf) + SEND_TAG);
    //uint8_t* dynamic_modulation_buffer = (((uint8_t *)BigBuf) + SEND_TAG_MOD);
    #define DYNAMIC_RESPONSE_BUFFER_SIZE 256 
	#define DYNAMIC_MODULATION_BUFFER_SIZE 2048 
	uint8_t dynamic_response_buffer[DYNAMIC_RESPONSE_BUFFER_SIZE];
	uint8_t dynamic_modulation_buffer[DYNAMIC_MODULATION_BUFFER_SIZE];
	tag_response_info_t dynamic_response_info = {
		.response = dynamic_response_buffer,
		.response_n = 0,
		.modulation = dynamic_modulation_buffer,
		.modulation_n = 0
	};
	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	size_t len = 0;
	// To control where we are in the protocol
	int order = 0;
	int lastorder;

	// Just to allow some checks
	int happened = 0;
	int happened2 = 0;

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

	tag_response_info_t* p_response;

	for(;;) {
		// Clean receive command buffer
		
		if(!GetIso14443aCommandFromReader(receivedCmd, &len, RECV_CMD_SIZE*4,5000)) {
			DbpString("timeout");
			break;
		}
        
        p_response = NULL;
		
		// Okay, look at the command now.
		lastorder = order;
		if(receivedCmd[0] == 0x26) { // Received a REQUEST
			p_response = &responses[0]; order = 1;
		} else if(receivedCmd[0] == 0x52) { // Received a WAKEUP
			p_response = &responses[0]; order = 6;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
			p_response = &responses[1]; order = 2;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x95) { // Received request for UID (cascade 2)
			p_response = &responses[2]; order = 20;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
			p_response = &responses[4]; order = 3;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x95) {	// Received a SELECT (cascade 2)
			p_response = &responses[5]; order = 30;
		} 
        else if(receivedCmd[0] == 0xB2){
            if(order == 4) { //send NACK, no command sent	
            }
            else{ //send last command again
			    p_response = &responses[7]; order = 30;
            }
        }  
        else if(receivedCmd[0] == 0xB3) {	// Received a SELECT (cascade 2)
            if(order == 4 ) { //send NACK, no command sent	
		    }
            else{ //send last command again
			    p_response = &responses[8]; order = 30;
            }		
        } 
        else if(receivedCmd[0] == 0xD0) {	// Received a SELECT (cascade 2)
			    p_response = &responses[9]; order = 30;
        }
        else if(receivedCmd[0] == 0xD1) {	// Received a SELECT (cascade 2)
			    p_response = &responses[10]; order = 30;
        }
        else if(receivedCmd[0] == 0xC2) {	// Received a DESELECT 
			    p_response = &responses[11]; order = 30;
        } 
        else if(receivedCmd[0] == 0xF2) {
            p_response = &responses[12]; order = 30;       
        }     
        else if(receivedCmd[0] == 0x0E) {
            p_response = &responses[13]; order = 30;       
        }else if(receivedCmd[0] == 0x30) {	// Received a (plain) READ
			//EmSendCmdEx(data+(4*receivedCmd[0]),16,false);
			// Dbprintf("Read request from reader: %x %x",receivedCmd[0],receivedCmd[1]);
			// We already responded, do not send anything with the EmSendCmd14443aRaw() that is called below
			p_response = NULL;}
		 else if(receivedCmd[0] == 0x50) {	// Received a HALT
//			DbpString("Reader requested we HALT!:");
			p_response = NULL;
		} else if(receivedCmd[0] == 0x60 || receivedCmd[0] == 0x61) {	// Received an authentication request
			p_response = &responses[5]; order = 7;
		} else if(receivedCmd[0] == 0xE0) {	
            // Received a RATS request
            { //send ATS
				p_response = &responses[6]; 
			}
		}  
        else {
			// Check for ISO 14443A-4 compliant commands, look at left nibble
			switch (receivedCmd[0]) {
                case 0x02:
				case 0x03: { // Readers sends deselect command
                    dynamic_response_info.response[0] = receivedCmd[0];
				    if(receivedCmd[1] == 0x00){
                        if(receivedCmd[2] == 0xA4){ //SELECT AID
				            uint8_t template6F[] = {0x6F,0x00}; 
                            uint8_t templateA5[] = {0xA5,0x00}; 
                            uint8_t tagBF0C[] = {0xBF,0x0C,0x00};
                            uint8_t tag84[] = {0x84, 0x00};
                            if(receivedCmd[6] == 0x32 ){ //2PAY DFE present 
                                 //generate response
                                 //save the current 84 tag (AID)
                                 uint8_t tag84backup[currentcard.tag_84_len];
                                 uint8_t tag84backuplen; 
                                 memcpy(tag84backup, currentcard.tag_84, currentcard.tag_84_len);
                                 tag84backuplen = currentcard.tag_84_len;
                                 memcpy(currentcard.tag_84, currentcard.tag_DFName, currentcard.tag_DFName_len);  
                                 currentcard.tag_84_len = currentcard.tag_DFName_len;
  
                                //generate A5 template(BF0C) 
                                 emv_generatetemplate(templateA5,&currentcard,tagvalbuffer,&tagvallen, 1, tagBF0C);
                                 memcpy(currentcard.tag_A5, tagvalbuffer+2, tagvallen-2);
                                 currentcard.tag_A5_len = tagvallen-2;
                                 //generate 6F template(84,A5)  
                                 emv_generatetemplate(template6F,&currentcard,currentcard.tag_6F ,&currentcard.tag_6F_len, 2, tag84, templateA5);
                                 //replace the AID tag
                                 memcpy(currentcard.tag_84, tag84backup, tag84backuplen);
                                 currentcard.tag_84_len = tag84backuplen;
                                 //transmit the response 
                                 dynamic_response_info.response_n = 1 + currentcard.tag_6F_len;
                                 memcpy(&dynamic_response_info.response[1], currentcard.tag_6F,currentcard.tag_6F_len); 
                                 //append status OK message 
                                 memcpy(&dynamic_response_info.response[1+currentcard.tag_6F_len], SW12_OK, 2); 
                                 dynamic_response_info.response_n += 2; 
                            }
                            else if(receivedCmd[6] == currentcard.tag_84[0]){ //select AID detected
                                memset(&dynamic_response_info.response[1], 0x41, 253);
                                dynamic_response_info.response_n = 254; 
                                //uint8_t tag50[] = {0x50, 0x00}; 
                                //uint8_t tag87[] = {0x87, 0x00}; 
                                //uint8_t tag9F38[] = {0x9F, 0x38,0x00};
                                //uint8_t tag5F2D[] = {0x5F,0x2D,0x00};
                                //uint8_t tag9F11[] = {0x9F, 0x11, 0x00};
                                //uint8_t tag9F12[] = {0x9F, 0x12, 0x00}; 
                                ////memset(&dynamic_response_info.response[1], 0x41, 62);
                                ////dynamic_response_info.response_n = 62+1; 
                                //emv_generatetemplate(templateA5,&currentcard,tagvalbuffer,&tagvallen, 6, tag50, tag87, tag9F38, tag5F2D, tag9F11, tag9F12);
                                // memcpy(currentcard.tag_A5, tagvalbuffer+2, tagvallen-2);
                                // currentcard.tag_A5_len = tagvallen-2;
                                // //generate 6F template(84,A5)  
                                // emv_generatetemplate(template6F,&currentcard,currentcard.tag_6F ,&currentcard.tag_6F_len, 2, tag84, templateA5);
                                // //transmit the response 
                                // dynamic_response_info.response_n = 1 + currentcard.tag_6F_len;
                                // memcpy(&dynamic_response_info.response[1], currentcard.tag_6F,currentcard.tag_6F_len); 
                                // //append status OK message 
                                // memcpy(&dynamic_response_info.response[1+currentcard.tag_6F_len], SW12_OK, 2); 
                                // dynamic_response_info.response_n += 2;    
                                // //Dbhexdump(dynamic_response_info.response_n, dynamic_response_info.response, false);            
                            }
                        } 
                        else if(receivedCmd[2] == 0xB2){
                            uint8_t template70[] = {0x70,0x00};
                            if(receivedCmd[4] == 0x0C) { //SFI 1
                                if(receivedCmd[3] == 0x01){ //record 1 
                                    LED_C_ON(); 
                                    uint8_t tag57[] = {0x57,0x00};
                                    uint8_t tag5F20[] = {0x5F, 0x20,0x00};
                                    uint8_t tag9F1F[] = {0x9F, 0x1F,0x00};
                                    emv_generatetemplate(template70, &currentcard, tagvalbuffer, &tagvallen, 3, tag57, tag5F20, tag9F1F);
                                    dynamic_response_info.response_n = 1 + currentcard.tag_70_len;
                                    memcpy(&dynamic_response_info.response[1], tagvalbuffer, tagvallen);
                                    memcpy(&dynamic_response_info.response[1+tagvallen], SW12_OK, 2); 
                                    dynamic_response_info.response_n += 2;    
                                    LED_C_OFF(); 
                                }     
                                else if(receivedCmd[3] == 0x02){ //record 1 
                                    uint8_t tag57[] = {0x57,0x00};
                                    uint8_t tag5F20[] = {0x5F, 0x20,0x00};
                                    uint8_t tag9F1F[] = {0x9F, 0x1F,0x00};
                                    emv_generatetemplate(template70, &currentcard, tagvalbuffer, &tagvallen, 3, tag57, tag5F20, tag9F1F);
                                    dynamic_response_info.response_n = 1 + tagvallen;
                                    memcpy(&dynamic_response_info.response[1], tagvalbuffer, tagvallen);
                                    memcpy(&dynamic_response_info.response[1+tagvallen], SW12_OK, 2); 
                                    dynamic_response_info.response_n += 2;    
                                    LED_C_OFF(); 
                                }
                            }
                        break; 
                        }
                        break;  
                    } 
                    else if(receivedCmd[1] == 0x80){
                        switch(receivedCmd[2]){
                            case 0x2A: //COMPUTE CRYPTOGRAPHIC CHECKSUM 
                                break;
                            case 0xAE: //GENERATE AC
                                break;
                            case 0xA8: //GET PROCESSING OPTIONS
                                memcpy(&dynamic_response_info.response[1], PIN_BLOCKED, 2);
                                dynamic_response_info.response_n = 3; 
                                //uint8_t template77[] = {0x77,0x00};
                                //uint8_t tag82[] = {0x82,0x00};
                                //uint8_t tag94[] = {0x94, 0x20,0x00};
                                //emv_generatetemplate(template77, &currentcard, tagvalbuffer, &tagvallen, 2, tag82, tag94);
                                //dynamic_response_info.response_n = 1 + currentcard.tag_77_len;
                                //memcpy(&dynamic_response_info.response[1], currentcard.tag_77, currentcard.tag_77_len);
                                //memcpy(&dynamic_response_info.response[1+currentcard.tag_77_len], SW12_OK, 2); 
                                //dynamic_response_info.response_n += 2;    
                                break;
                            default: 
                                dynamic_response_info.response[0] = receivedCmd[0];
                                memcpy(&dynamic_response_info.response[1], SW12_NOT_SUPPORTED, 2);
                                dynamic_response_info.response_n = 3;
                                break;
                        } 
                        break;
                    }	
                } break;  
                default:
                {
				    // Never seen this command before
				    dynamic_response_info.response[0] = receivedCmd[0];
                    memcpy(&dynamic_response_info.response[1], SW12_NOT_SUPPORTED, 2);
                    dynamic_response_info.response_n = 3;
                    if (tracing) {
				        LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, &Uart.parityBits, TRUE);
				        LogTrace(NULL, 0, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, NULL, TRUE);
				    }
				} break;
			}
			if (dynamic_response_info.response_n > 0) {
				// Copy the CID from the reader query

				// Add CRC bytes, always used in ISO 14443A-4 compliant cards
				AppendCrc14443a(dynamic_response_info.response,dynamic_response_info.response_n);
				dynamic_response_info.response_n += 2;
                  
				if (prepare_tag_modulation(&dynamic_response_info,DYNAMIC_MODULATION_BUFFER_SIZE) == false) {
					Dbprintf("Error preparing tag response");
					if (tracing) {
						LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, &Uart.parityBits, TRUE);
						LogTrace(NULL, 0, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, NULL, TRUE);
					}
					break;
				}
				p_response = &dynamic_response_info;
                
                //clear last response
                //memset(receivedCmd, 0x00,10); //clear last received command 
                //Dbprintf("Send Command="); 
                //Dbhexdump(dynamic_response_info.response_n, dynamic_response_info.response, false);
            }
		}

		// Count number of wakeups received after a halt
		if(order == 6 && lastorder == 5) { happened++; }

		// Count number of other messages after a halt
		if(order != 6 && lastorder == 5) { happened2++; }

		if (p_response != NULL) {
                EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, (receivedCmd[0] == 0x52) || (receivedCmd[0]==0x26));
                dynamic_response_info.response_n = 0;
                dynamic_response_info.modulation_n=0;
		        if (tracing) {
			        EmLogTrace(Uart.output, 
                                Uart.len, 
                                Uart.startTime*16-DELAY_AIR2ARM_AS_TAG,
                                Uart.endTime*16-DELAY_AIR2ARM_AS_TAG, 
                                &Uart.parityBits, 
                                p_response->response,
                                p_response->response_n, 
                                LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG, 
                                (LastTimeProxToAirStart + p_response->ProxToAirDuration) * 16 +DELAY_ARM2AIR_AS_TAG, 
                                NULL); 	
                }
        }
    }    
}
*/
//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
/*

void EMVFuzz_RATS(uint8_t ratslen, uint8_t* RATS)
{
    // Enable and clear the trace
	//iso14a_clear_trace();
	//iso14a_set_tracing(FALSE);
	//iso14a_set_tracing(TRUE);
    UartReset();
    DemodReset();
    size_t len; 
	uint8_t sak;
    //copy input rats into a buffer
    uint8_t ratscmd[ratslen+2]; 
    memcpy(ratscmd, RATS, ratslen);
	
    // The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t atqa[2];
	atqa[0] = 0x04;
	atqa[1] = 0x00;
	sak = 0x28;
	
	// The second response contains the (mandatory) first 24 bits of the UID
	uint8_t uid0[5] = {0x12,0x34,0x56,0x78,0x9A};

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	uid0[4] = uid0[0] ^ uid0[1] ^ uid0[2] ^ uid0[3];

	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t sakresponse[3];
	sakresponse[0] = sak;
	ComputeCrc14443(CRC_14443_A, sakresponse, 1, &sakresponse[1], &sakresponse[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
    
    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; //ACK packets 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1);
    
    AppendCrc14443a(ratscmd, sizeof(ratscmd)-2); 
    //ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);

    //handle the PPS selection
    uint8_t PPSR[3] = {0xD0,0x00,0x00};
    AppendCrc14443a(PPSR, 1);
    
	//#define TAG_RESPONSE_COUNT 9 
	tag_response_info_t responses[7] = {
		{ .response = atqa,  .response_n = sizeof(atqa)  },  // Answer to request - respond with card type
		{ .response = uid0,  .response_n = sizeof(uid0)  },  // Anticollision cascade1 - respond with uid
		{ .response = sakresponse,  .response_n = sizeof(sakresponse)  },  // Acknowledge select - cascade 1
		{ .response = ratscmd,  .response_n = sizeof(ratscmd)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = sizeof(ACK1)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK2,  .response_n = sizeof(ACK2)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = PPSR,  .response_n = sizeof(PPSR)  },  // dummy ATS (pseudo-ATR), answer to RATS
	};

	// Reset the offset pointer of the free buffer
	reset_free_buffer();
  
	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
    for (size_t i=0; i<7; i++) {
		prepare_allocated_tag_modulation(&responses[i]);
	}
	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	//uint16_t len = 0;

	// To control where we are in the protocol
	int order = 0;
	// Just to allow some checks

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
	tag_response_info_t* p_response;
    
	LED_C_ON();
	// Clean receive command buffer
    for(;;){  
        if(!GetIso14443aCommandFromReader(receivedCmd, &len, RECV_CMD_SIZE, 250)){
            //Dbprintf("timeout");
            break;
        } 
	    p_response = NULL;
        //Dbhexdump(len, receivedCmd,false); 
        if((receivedCmd[0] == 0x26) || (receivedCmd[0] == 0x52)) { // Received a REQUEST
	    	p_response = &responses[0]; order = 1;
        }	
	    if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
            p_response = &responses[1]; order = 2; //send the UID 
	    }  
        if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
	    	p_response = &responses[2]; order = 3; //send the SAK
	    }
        if(receivedCmd[0] == 0xD0) {	// Received a PPS request
	    	//p_response = &responses[6]; order = 70;
	    	p_response = &responses[6]; order = 70;
	    } 
	    if(receivedCmd[0] == 0xE0) {	// Received a RATS request
	    	//p_response = &responses[6]; order = 70;
	    	p_response = &responses[3]; order = 70;
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, (receivedCmd[0] == 0x52) || (receivedCmd[0] == 0x26));
            break;
	    }
        if(p_response != NULL){
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, (receivedCmd[0] == 0x52) || (receivedCmd[0] == 0x26));
            EmLogTrace(Uart.output, 
                                Uart.len, 
                                Uart.startTime*16-DELAY_AIR2ARM_AS_TAG,
                                Uart.endTime*16-DELAY_AIR2ARM_AS_TAG, 
                                &Uart.parityBits, 
                                p_response->response,
                                p_response->response_n, 
                                LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG, 
                                (LastTimeProxToAirStart + p_response->ProxToAirDuration) * 16 +DELAY_ARM2AIR_AS_TAG, 
                                NULL);}
        else{
            //Dbprintf("finished"); 
            break;
        } 
    } 
    //Dbprintf("finished"); 
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_C_OFF();
    return;
}
*/
/*
void EMVFuzz_PPSE(uint8_t PPSElen, uint8_t* PPSE)
{
    // Enable and clear the trace
	//iso14a_clear_trace();
	//iso14a_set_tracing(FALSE);
	//iso14a_set_tracing(TRUE);
    UartReset();
    DemodReset();
    uint8_t framesize = 64; //set frame size to 64bits 
    size_t len; 
	uint8_t sak;
    //copy input rats into a buffer
    uint8_t ratscmd[] = {0x0b, 0x78, 0x80, 0x81, 0x02, 0x4b, 0x4f, 0x4e, 0x41, 0x14, 0x11, 0x8a, 0x76}; 
    //ratslen = 4; 
    //memcpy(ratscmd, RATS, ratslen);
	
    // The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t atqa[2];
	atqa[0] = 0x04;
	atqa[1] = 0x00;
	sak = 0x28;
	
	// The second response contains the (mandatory) first 24 bits of the UID
	uint8_t uid0[5] = {0x12,0x34,0x56,0x78,0x9A};

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	uid0[4] = uid0[0] ^ uid0[1] ^ uid0[2] ^ uid0[3];

	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t sakresponse[3];
	sakresponse[0] = sak;
	ComputeCrc14443(CRC_14443_A, sakresponse, 1, &sakresponse[1], &sakresponse[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
    
    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; //ACK packets 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1);
    
    //AppendCrc14443a(ratscmd, sizeof(ratscmd)-2); 
    //ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);

    //handle the PPS selection
    uint8_t PPSR[3] = {0xD0,0x00,0x00};
    AppendCrc14443a(PPSR, 1);
    
	//#define TAG_RESPONSE_COUNT 9 
	tag_response_info_t responses[7] = {
		{ .response = atqa,  .response_n = sizeof(atqa)  },  // Answer to request - respond with card type
		{ .response = uid0,  .response_n = sizeof(uid0)  },  // Anticollision cascade1 - respond with uid
		{ .response = sakresponse,  .response_n = sizeof(sakresponse)  },  // Acknowledge select - cascade 1
		{ .response = ratscmd,  .response_n = sizeof(ratscmd)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = sizeof(ACK1)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK2,  .response_n = sizeof(ACK2)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = PPSR,  .response_n = sizeof(PPSR)  },  // dummy ATS (pseudo-ATR), answer to RATS
	};

	// Reset the offset pointer of the free buffer
	reset_free_buffer();
  
	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
    for (size_t i=0; i<7; i++) {
		prepare_allocated_tag_modulation(&responses[i]);
	}
	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	//uint16_t len = 0;

	// To control where we are in the protocol
	int order = 0;
	// Just to allow some checks

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
	tag_response_info_t* p_response;
    
	LED_C_ON();
	// Clean receive command buffer
    for(;;){  
        if(!GetIso14443aCommandFromReader(receivedCmd, &len, RECV_CMD_SIZE, 250)){
            //Dbprintf("timeout");
            break;
        } 
	    p_response = NULL;
        Dbhexdump(len, receivedCmd,false); 
        if((receivedCmd[0] == 0x26) || (receivedCmd[0] == 0x52)) { // Received a REQUEST
	    	p_response = &responses[0]; order = 1;
        }	
	    if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
            p_response = &responses[1]; order = 2; //send the UID 
	    }  
        if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
	    	p_response = &responses[2]; order = 3; //send the SAK
	    }
        if(receivedCmd[0] == 0xD0) {	// Received a PPS request
	    	//p_response = &responses[6]; order = 70;
	    	p_response = &responses[6]; order = 70;
	    } 
	    if(receivedCmd[0] == 0xE0) {	// Received a RATS request
	    	p_response = &responses[3]; order = 70;
            //break;
	    }
        else if(receivedCmd[0] == 0xB2){
            if(order == 4) { //send NACK, no command sent	
            }
            else{ //send last command again
			    p_response = &responses[4]; order = 30;
            }
        }  
        else if(receivedCmd[0] == 0xB3) {	// Received a SELECT (cascade 2)
            if(order == 4 ) { //send NACK, no command sent	
		    }
            else{ //send last command again
			    p_response = &responses[5]; order = 30;
        }		
        }if((receivedCmd[0] == 0x02) || (receivedCmd[0] == 0x03)){
            p_response = NULL;
            EmSendCmdChain(PPSE, PPSElen, framesize);  
            break; //end the process and turn off the field 
        }
        if(p_response != NULL){ //send the modulated command
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, (receivedCmd[0] == 0x52) || (receivedCmd[0] == 0x26));
            parity_t swappedparity;
            ParityReset(&swappedparity);
            GetParity(p_response->response, p_response->response_n, &swappedparity);
            SwapBitsParity(&swappedparity);
            EmLogTrace(Uart.output, 
                                Uart.len, 
                                Uart.startTime*16-DELAY_AIR2ARM_AS_TAG,
                                Uart.endTime*16-DELAY_AIR2ARM_AS_TAG, 
                                &Uart.parityBits, 
                                p_response->response,
                                p_response->response_n, 
                                LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG, 
                                (LastTimeProxToAirStart + p_response->ProxToAirDuration) * 16 +DELAY_ARM2AIR_AS_TAG, 
                                &swappedparity); 
        }
        else{
            //Dbprintf("finished"); 
            //break;
        } 
    } 
    Dbprintf("finished"); 
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_C_OFF();
    return;
}
*/

static uint8_t* free_buffer_pointer;

//function to retrieve random number from the terminal
//this is supplied in the compute cryptographic checksum command
void EMVgetUDOL()
{
    /* 
    uint8_t receivedCmd[MAX_FRAME_SIZE];
    uint8_t receivedCmd_par[MAX_FRAME_SIZE];
    uint8_t response[MAX_FRAME_SIZE];
    uint8_t response_par[MAX_FRAME_SIZE];
`   */
    //uint8_t* free_buffer_pointer;
    uint8_t atqa[] = {0x04, 0x00};
	uint8_t uid0[5] = {0x12,0x34,0x56,0x78,0x9A};
	uid0[4] = uid0[0] ^ uid0[1] ^ uid0[2] ^ uid0[3];
    //copy input rats into a buffer
    uint8_t ratscmd[] = {0x0b, 0x78, 0x80, 0x81, 0x02, 0x4b, 0x4f, 0x4e, 0x41, 0x14, 0x11, 0x8a, 0x76}; 
	
	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t sakresponse[3];
	sakresponse[0] = 0x28;
	ComputeCrc14443(CRC_14443_A, sakresponse, 1, &sakresponse[1], &sakresponse[2]);

    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; //ACK packets 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1);
    
    //handle the PPS selection
    uint8_t PPSR[3] = {0xD0,0x00,0x00};
    AppendCrc14443a(PPSR, 1);
/*  
    //canned EMV responses
    uint8_t selectPPSE[] = {
0x6f,0x2f,0x84,0x0e,0x32,0x50,0x41,0x59,
0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,
0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
0x65,0x72,0x43,0x61,0x72,0x64,0x87,0x01,
0x01,0x90,0x00};
*/
    uint8_t selectPPSE[] = {
0x6f,0x2f,0x84,0x0e,0x32,0x50,0x41,0x59,
0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,
0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00};
//0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
//0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
//0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
//0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00,
//0x6f,0x2f,0x84,0x0e,0x32,0x50,0x41,0x59,
//0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,
//0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
//0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
//0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
//0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00};
/*
0x6f,0x2f,0x84,0x0e,0x32,0x50,0x41,0x59,
0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,
0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00,
0x6f,0x2f,0x84,0x0e,0x32,0x50,0x41,0x59};
0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,
0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00,
0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00,
0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00};
*/
/*
//0x01,0x90,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t selectPPSE[60] = {
0x6f,0x38,0x84,0x07,0xa0,0x00,0x00,0x00,
0x04,0x10,0x10,0xa5,0x2d,0x50,0x0a,0x4d,
0x61,0x73,0x74,0x65,0x72,0x43,0x61,0x72,
0x64,0x87,0x01,0x01,0x5f,0x2d,0x02,0x65,
0x6e,0x9f,0x11,0x01,0x01,0x9f,0x12,0x0a,
0x4e,0x41,0x42,0x20,0x43,0x72,0x65,0x64,
0x69,0x74,0xbf,0x0c,0x05,0x9f,0x4d,0x02,
0x0b,0x0a,0x90,0x0};
    uint8_t selectAID[] = {
0x6f,0x38,0x84,0x07,0xa0,0x00,0x00,0x00,
0x04,0x10,0x10,0xa5,0x2d,0x50,0x0a,0x4d,
0x61,0x73,0x74,0x65,0x72,0x43,0x61,0x72,
0x64,0x87,0x01,0x01,0x5f,0x2d,0x02,0x65,
0x6e,0x9f,0x11,0x01,0x01,0x9f,0x12,0x0a,
0x4e,0x41,0x42,0x20,0x43,0x72,0x65,0x64,
0x69,0x74,0xbf,0x0c,0x05,0x9f,0x4d,0x02,
0x0b,0x0a,0x90,0x0};
    uint8_t getProcessing[] = {
0x77,0x16,0x82,0x02,0x19,0x80,0x94,0x10,
0x08,0x01,0x01,0x00,0x10,0x01,0x01,0x01,
0x18,0x01,0x02,0x00,0x20,0x01,0x02,0x00,
0x90,0x00};
    uint8_t readRec11[] = {
0x70,0x81,0x8d,0x9f,0x6c,0x02,0x00,0x01,
0x9f,0x62,0x06,0x00,0x00,0x00,0x00,0x01,
0xc0,0x9f,0x63,0x06,0x00,0x00,0x00,0xf8,
0x00,0x00,0x56,0x4c,0x42,0x35,0x35,0x35,
0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,
0x35,0x35,0x35,0x35,0x35,0x5e,0x20,0x2f,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x5e,0x31,0x37,0x30,0x36,0x32,0x30,0x31,
0x30,0x30,0x30,0x30,0x30,0x20,0x20,0x20,
0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,
0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,
0x9f,0x64,0x01,0x03,0x9f,0x65,0x02,0x00,
0xe0,0x9f,0x66,0x02,0x1f,0x00,0x9f,0x6b,
0x13,0x53,0x13,0x58,0x55,0x12,0x49,0x66,
0x14,0xd1,0x70,0x62,0x01,0x00,0x00,0x00,
0x00,0x01,0x00,0x0f,0x9f,0x67,0x01,0x03,
0x90,0x00}; 
   uint8_t computeCC[] = {
0x77,0x0f,0x9f,0x61,0x02,0x4a,0x49,0x9f,
0x60,0x02,0xb8,0xf0,0x9f,0x36,0x02,0x07,
0xe0,0x90,0x00};
*/ 
	#define CANNED_RESPONSE_COUNT 7 
	tag_response_info_t responses[7] = {
		{ .response = atqa,  .response_n = sizeof(atqa)  },  // Answer to request - respond with card type
		{ .response = uid0,  .response_n = sizeof(uid0)  },  // Anticollision cascade1 - respond with uid
		{ .response = sakresponse,  .response_n = sizeof(sakresponse)  },  // Acknowledge select - cascade 1
		{ .response = ratscmd,  .response_n = sizeof(ratscmd)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = sizeof(ACK1)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK2,  .response_n = sizeof(ACK2)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = PPSR,  .response_n = sizeof(PPSR)  },  // dummy ATS (pseudo-ATR), answer to RATS
	};
    //calculated length of predone responses
    uint16_t allocatedtag_len = 0; 
    for(int i=0;i<CANNED_RESPONSE_COUNT;i++){
        allocatedtag_len += responses[i].response_n;
    }
    //get the maximum length of the responses  
    uint16_t allocatedtagmod_len  = (allocatedtag_len*8) +(allocatedtag_len) + (CANNED_RESPONSE_COUNT * 3);

    clear_trace(); 
    set_tracing(TRUE);
    
    //setup dynamic_reponse buffer
    uint8_t dynamic_response_buffer[MAX_FRAME_SIZE];
    uint8_t dynamic_modulation_buffer[MAX_FRAME_SIZE*8];
    
    tag_response_info_t dynamic_response_info = {
        .response = dynamic_response_buffer,
        .response_n = 0,
        .modulation = dynamic_modulation_buffer,
        .modulation_n = 0
    };	
    
    BigBuf_free_keep_EM();
    uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
    uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);
    
    free_buffer_pointer = BigBuf_malloc(allocatedtagmod_len);

    //uint8_t* free_buffer_pointer = BigBuf_malloc(512);
  
    // Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
    for (int i=0; i<CANNED_RESPONSE_COUNT; i++) {
        responses[i].modulation = free_buffer_pointer;
        prepare_tag_modulation(&responses[i], allocatedtagmod_len); 
        free_buffer_pointer += ToSendMax;
    }
    //reset the ToSend Buffer
    ToSendReset();    
	// To control where we are in the protocol
	//int order = 0;
    int selectOrder = 0; 
    //int lastorder;	
    int len; 

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
	tag_response_info_t* p_response;
    
	LED_C_ON();
	// Clean receive command buffer
    for(;;)
    {  
        if(!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)){
            Dbprintf("Button press");
	        LED_C_OFF();
            break;
        } 
	    //Dbhexdump(len, receivedCmd, false); 
        p_response = NULL;
        //lastorder = order; 
        if(receivedCmd[0] == 0x26) { // Received a REQUEST
	    	p_response = &responses[0]; //order = 1;
        }	
	    else if(receivedCmd[0] == 0x52) { // Received a REQUEST
            p_response = &responses[0]; //order = 6;
        }
        else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
            p_response = &responses[1]; //order = 2; //send the UID 
	    }  
        else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
	    	p_response = &responses[2]; //order = 3; //send the SAK
	    }
        else if(receivedCmd[0] == 0xB2){
			p_response = &responses[4]; //order = 30;
        }  
        else if(receivedCmd[0] == 0xB3) {	// Received a SELECT (cascade 2)
		    p_response = &responses[5]; //order = 30;
        }
        else if(receivedCmd[0] == 0xD0) {	// Received a PPS request
	    	p_response = &responses[6]; //order = 70;
	    } 
	    else if(receivedCmd[0] == 0xE0) {	// Received a RATS request
	    	p_response = &responses[3]; //order = 70;
	    }
        else if(receivedCmd[0] == 0x50){
            p_response = NULL;
        } 
        
        else if((receivedCmd[0] == 0x02) || (receivedCmd[0] == 0x03))
        { //I Frame
            dynamic_response_info.response_n = 0; 
            dynamic_response_info.response[0] = receivedCmd[0]; // copy PCB 
            dynamic_response_info.response_n++; 
            switch(receivedCmd[1]) {
                case 0x00: 
                    switch(receivedCmd[2]){
                        case 0xA4: //select
                            if(selectOrder == 0)
                                memcpy(dynamic_response_info.response+1, selectPPSE, sizeof(selectPPSE));
                                dynamic_response_info.response_n += sizeof(selectPPSE);
                                selectOrder = 1;
                            break;
                        case 0xB2: //read record
                            break;
                        default:
                            break;
                    }
                    break; 
                case 0x80:
                    switch(receivedCmd[2]){
                        case 0x2A: //compute cryptographic checksum
                            break;
                        case 0xAE: //generate AC
                            break;
                        case 0xA8: //get processing options
                            break; 
                         default:
                            break;
                    }
                    break;
                default:
                    break;
            }
        } 
        if(dynamic_response_info.response_n > 0)
        {
            AppendCrc14443a(dynamic_response_info.response,dynamic_response_info.response_n);
            dynamic_response_info.response_n += 2;
            //Dbhexdump(dynamic_response_info.response_n,dynamic_response_info.response, false); 
            //reset the ToSend Buffer
            ToSendReset(); 
            //prepare the tag modulation 
            if(prepare_tag_modulation(&dynamic_response_info,TOSEND_BUFFER_SIZE) == false) 
            {
                 Dbprintf("Error preparing tag response");
                 break;
            }
            p_response = &dynamic_response_info;
        } 
        
        if(p_response != NULL){ //send the modulated command
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, receivedCmd[0] == 0x52);
            //EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, false);
             
            //uint8_t par[MAX_PARITY_SIZE];
            // 
            //GetParity(p_response->response, p_response->response_n, par);
            //
            ////Dbhexdump(p_response->response_n, p_response->response, false); 
            ////LogReceiveTrace(); 
            //if(tracing){ 
            //    LogSniffTrace(p_response->response_n, p_response->response,  par);
            //}  
            
        }
    } 
    Dbprintf("finished"); 
    //FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    BigBuf_free_keep_EM();	
    LED_C_OFF();
}

void EMVcorrect()
{
    //uint8_t* free_buffer_pointer;
    uint8_t atqa[] = {0x04, 0x00};
	uint8_t uid0[5] = {0x12,0x34,0x56,0x78,0x9A};
	uid0[4] = uid0[0] ^ uid0[1] ^ uid0[2] ^ uid0[3];
    //copy input rats into a buffer
    uint8_t ratscmd[] = {0x0b, 0x78, 0x80, 0x81, 0x02, 0x4b, 0x4f, 0x4e, 0x41, 0x14, 0x11, 0x8a, 0x76}; 
	
	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t sakresponse[3];
	sakresponse[0] = 0x28;
	ComputeCrc14443(CRC_14443_A, sakresponse, 1, &sakresponse[1], &sakresponse[2]);

    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; //ACK packets 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1);
    
    //handle the PPS selection
    uint8_t PPSR[3] = {0xD0,0x00,0x00};
    AppendCrc14443a(PPSR, 1);
/*  
    //canned EMV responses
    uint8_t selectPPSE[] = {
0x6f,0x2f,0x84,0x0e,0x32,0x50,0x41,0x59,
0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,
0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
0x65,0x72,0x43,0x61,0x72,0x64,0x87,0x01,
0x01,0x90,0x00};
*/
    uint8_t selectPPSE[] = {
0x6f,0x2f,0x84,0x0e,0x32,0x50,0x41,0x59,
0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,
0x30,0x31,0xa5,0x1d,0xbf,0x0c,0x1a,0x61,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x18,0x4f,0x07,0xa0,0x00,0x00,0x00,0x04,
0x10,0x10,0x50,0x0a,0x4d,0x61,0x73,0x74,
0x65,0x72,0x43,0x61,0x72,0x64,0x90,0x00};

	#define CANNED_RESPONSE_COUNT 7 
	tag_response_info_t responses[7] = {
		{ .response = atqa,  .response_n = sizeof(atqa)  },  // Answer to request - respond with card type
		{ .response = uid0,  .response_n = sizeof(uid0)  },  // Anticollision cascade1 - respond with uid
		{ .response = sakresponse,  .response_n = sizeof(sakresponse)  },  // Acknowledge select - cascade 1
		{ .response = ratscmd,  .response_n = sizeof(ratscmd)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = sizeof(ACK1)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK2,  .response_n = sizeof(ACK2)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = PPSR,  .response_n = sizeof(PPSR)  },  // dummy ATS (pseudo-ATR), answer to RATS
	};
    //calculated length of predone responses
    uint16_t allocatedtag_len = 0; 
    for(int i=0;i<CANNED_RESPONSE_COUNT;i++){
        allocatedtag_len += responses[i].response_n;
    }
    //get the maximum length of the responses  
    uint16_t allocatedtagmod_len  = (allocatedtag_len*8) +(allocatedtag_len) + (CANNED_RESPONSE_COUNT * 3);

    clear_trace(); 
    set_tracing(TRUE);
    
    //setup dynamic_reponse buffer
    uint8_t dynamic_response_buffer[MAX_FRAME_SIZE];
    uint8_t dynamic_modulation_buffer[MAX_FRAME_SIZE*8];
    
    tag_response_info_t dynamic_response_info = {
        .response = dynamic_response_buffer,
        .response_n = 0,
        .modulation = dynamic_modulation_buffer,
        .modulation_n = 0
    };	
    
    BigBuf_free_keep_EM();
    uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
    uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);
    
    free_buffer_pointer = BigBuf_malloc(allocatedtagmod_len);

    //uint8_t* free_buffer_pointer = BigBuf_malloc(512);
  
    // Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
    for (int i=0; i<CANNED_RESPONSE_COUNT; i++) {
        responses[i].modulation = free_buffer_pointer;
        prepare_tag_modulation(&responses[i], allocatedtagmod_len); 
        free_buffer_pointer += ToSendMax;
    }
    //reset the ToSend Buffer
    ToSendReset();    
	// To control where we are in the protocol
	//int order = 0;
    int selectOrder = 0; 
    //int lastorder;	
    int len; 

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
	tag_response_info_t* p_response;
    
	LED_C_ON();
	// Clean receive command buffer
    for(;;)
    {  
        if(!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)){
            Dbprintf("Button press");
	        LED_C_OFF();
            break;
        } 
	    //Dbhexdump(len, receivedCmd, false); 
        p_response = NULL;
        //lastorder = order; 
        if(receivedCmd[0] == 0x26) { // Received a REQUEST
	    	p_response = &responses[0]; //order = 1;
        }	
	    else if(receivedCmd[0] == 0x52) { // Received a REQUEST
            p_response = &responses[0]; //order = 6;
        }
        else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
            p_response = &responses[1]; //order = 2; //send the UID 
	    }  
        else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
	    	p_response = &responses[2]; //order = 3; //send the SAK
	    }
        else if(receivedCmd[0] == 0xB2){
			p_response = &responses[4]; //order = 30;
        }  
        else if(receivedCmd[0] == 0xB3) {	// Received a SELECT (cascade 2)
		    p_response = &responses[5]; //order = 30;
        }
        else if(receivedCmd[0] == 0xD0) {	// Received a PPS request
	    	p_response = &responses[6]; //order = 70;
	    } 
	    else if(receivedCmd[0] == 0xE0) {	// Received a RATS request
	    	p_response = &responses[3]; //order = 70;
	    }
        else if(receivedCmd[0] == 0x50){
            p_response = NULL;
        } 
        
        else if((receivedCmd[0] == 0x02) || (receivedCmd[0] == 0x03))
        { //I Frame
            dynamic_response_info.response_n = 0; 
            dynamic_response_info.response[0] = receivedCmd[0]; // copy PCB 
            dynamic_response_info.response_n++; 
            switch(receivedCmd[1]) {
                case 0x00: 
                    switch(receivedCmd[2]){
                        case 0xA4: //select
                            if(selectOrder == 0)
                                memcpy(dynamic_response_info.response+1, selectPPSE, sizeof(selectPPSE));
                                dynamic_response_info.response_n += sizeof(selectPPSE);
                                selectOrder = 1;
                            break;
                        case 0xB2: //read record
                            break;
                        default:
                            break;
                    }
                    break; 
                case 0x80:
                    switch(receivedCmd[2]){
                        case 0x2A: //compute cryptographic checksum
                            break;
                        case 0xAE: //generate AC
                            break;
                        case 0xA8: //get processing options
                            break; 
                         default:
                            break;
                    }
                    break;
                default:
                    break;
            }
        } 
        if(dynamic_response_info.response_n > 0)
        {
            AppendCrc14443a(dynamic_response_info.response,dynamic_response_info.response_n);
            dynamic_response_info.response_n += 2;
            //Dbhexdump(dynamic_response_info.response_n,dynamic_response_info.response, false); 
            //reset the ToSend Buffer
            ToSendReset(); 
            //prepare the tag modulation 
            if(prepare_tag_modulation(&dynamic_response_info,TOSEND_BUFFER_SIZE) == false) 
            {
                 Dbprintf("Error preparing tag response");
                 break;
            }
            p_response = &dynamic_response_info;
        } 
        
        if(p_response != NULL){ //send the modulated command
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, receivedCmd[0] == 0x52);
            //EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, false);
             
            //uint8_t par[MAX_PARITY_SIZE];
            // 
            //GetParity(p_response->response, p_response->response_n, par);
            //
            ////Dbhexdump(p_response->response_n, p_response->response, false); 
            ////LogReceiveTrace(); 
            //if(tracing){ 
            //    LogSniffTrace(p_response->response_n, p_response->response,  par);
            //}  
            
        }
    } 
    Dbprintf("finished"); 
    //FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    BigBuf_free_keep_EM();	
    LED_C_OFF();
}
