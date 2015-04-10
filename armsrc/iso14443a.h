//---x_buffer_size) {--------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#ifndef __ISO14443A_H
#define __ISO14443A_H
#include "common.h"
#include "mifaresniff.h"

//ISO14443a states, used for Tag Emulation
#define REQA        0x0 //Request command 
#define SELUID1     0x10 //select UID level 1
#define SELUID2     0x11 //select UID level 1
#define SELUID3     0x12 //select UID level 1
#define SEL1        0x20 //Select cascade level 1
#define SEL2        0x21 //Select cascade level 2
#define SEL3        0x22 //Select cascade level 3
#define RATS        0x3 //Request for answer to select
#define PPS         0x4 //Protocol and parameter selection  
#define DESELECT    0x5  
#define HLTA        0x6 //halt 
#define WUPA        0x7 //wake-up
#define AUTH        0x8 //Authentication Request (Mifare)
#define RACK        0x9
#define RNAK        0xA
#define IBLOCK      0xB
 
typedef struct {
	enum {
		DEMOD_UNSYNCD,
		// DEMOD_HALF_SYNCD,
		// DEMOD_MOD_FIRST_HALF,
		// DEMOD_NOMOD_FIRST_HALF,
		DEMOD_MANCHESTER_DATA
	} state;
	uint16_t twoBits;
	uint16_t highCnt;
	uint16_t bitCount;
	uint16_t collisionPos;
	uint16_t syncBit;
	uint8_t  parityBits;
	uint8_t  parityLen;
	uint16_t shiftReg;
	uint16_t samples;
	uint16_t len;
	uint32_t startTime, endTime;
	uint8_t  *output;
	uint8_t  *parity;
} tDemod;

typedef enum {
	MOD_NOMOD = 0,
	MOD_SECOND_HALF,
	MOD_FIRST_HALF,
	MOD_BOTH_HALVES
	} Modulation_t;

typedef struct {
	enum {
		STATE_UNSYNCD,
		STATE_START_OF_COMMUNICATION,
		STATE_MILLER_X,
		STATE_MILLER_Y,
		STATE_MILLER_Z,
		// DROP_NONE,
		// DROP_FIRST_HALF,
		} state;
	uint16_t shiftReg;
	uint16_t bitCount;
	uint16_t len;
	uint16_t byteCntMax;
	uint16_t posCnt;
	uint16_t syncBit;
	uint8_t  parityBits;
	uint8_t  parityLen;
	uint16_t highCnt;
	uint16_t twoBits;
	uint32_t startTime, endTime;
    uint8_t *output;
	uint8_t *parity;
} tUart;

typedef struct {
  uint8_t* response;
  size_t   response_n;
  uint8_t* modulation;
  size_t   modulation_n;
  uint32_t ProxToAirDuration;
} tag_response_info_t;


extern byte_t oddparity (const byte_t bt);
extern void GetParity(const uint8_t *pbtCmd, uint16_t len, uint8_t *par);
extern void AppendCrc14443a(uint8_t *data, int len);

extern void ReaderTransmit(uint8_t *frame, uint16_t len, uint32_t *timing);
extern void ReaderTransmitBitsPar(uint8_t *frame, uint16_t bits, uint8_t *par, uint32_t *timing);
extern void ReaderTransmitPar(uint8_t *frame, uint16_t len, uint8_t *par, uint32_t *timing);
extern int ReaderReceive(uint8_t *receivedAnswer, uint8_t *par);

extern void iso14443a_setup(uint8_t fpga_minor_mode);
/*Peter Fillmore 2015 - added card id specifier*/
extern int iso14_apdu(uint8_t *cmd, uint16_t cmd_len,bool useCID, uint8_t CID, void *data);
extern int iso14443a_select_card(uint8_t *uid_ptr, iso14a_card_select_t *resp_data, uint32_t *cuid_ptr);
extern void iso14a_set_trigger(bool enable);

//added external reference for EMV
extern /*static*/ int EmGetCmd(uint8_t *received, uint16_t *len, uint8_t *parity);
extern int EmSendCmd(uint8_t *resp, uint16_t respLen);
extern int EmSendCmdEx(uint8_t *resp, uint16_t respLen, bool correctionNeeded);

extern bool prepare_allocated_tag_modulation(tag_response_info_t* response_info);

extern bool prepare_tag_modulation(tag_response_info_t* response_info, size_t max_buffer_size);

extern int GetIso14443aCommandFromReader(uint8_t *received, uint8_t *parity, int *len);
/*static*/ int EmSendCmd14443aRaw(uint8_t *resp, uint16_t respLen, bool correctionNeeded);
//logging functions
int LogReceiveTrace();
int LogSniffTrace(uint16_t tag_len, uint8_t* tag_data,  uint8_t* tag_parity);

#endif /* __ISO14443A_H */
