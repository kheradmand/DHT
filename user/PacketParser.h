#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "frame.h"
#include "sr_protocol.h"
#include "DHTNodeInfo.h"
using namespace std;

class SimulatedMachine;

class PacketParser{
private:
	SimulatedMachine* sm;
	bool sendFrame(Frame frame, ip_t dst);
    
    ip_t ip_src;
    ip_t ip_dst;
    
    port_t port_src;
    port_t port_dst;
    
    ip_t init_ip;
    port_t init_port;
    byte* key;
    uint16 control;
    byte flags;
    byte operation;
    uint32 N;
    
    pthread_t updateFinger_thread;

    
public:
	PacketParser(SimulatedMachine* _sm);
	bool parseFrame(Frame frame);
private:
	bool parseIPv4(Frame frame);
    bool parseUDP(Frame frame);
    bool parseDHT(Frame frame);
    bool parseDHTFindSuccessor(Frame frame);
    bool parseDHTUpdate(Frame frame);
    bool parseDHTGet(Frame frame);
    bool parseDHTSet(Frame frame);

    void fillDefaultDHTHeader(dht_hdr* header);
    bool sendDHTFindSuccessorResponse(pred_suc_info my_pred_suc);
    bool sendDHTFindSuccessorQuery(DHTNodeInfo target,bool init=0,byte* thekey=NULL);


    bool sendDHTPacket(Frame frame, ip_t target_ip, port_t taget_port);
    bool sendFrame(Frame frame);



    byte* getFingerStart(int index);


    void updateFinger(uint32 n);

    void ntoh_pred_suc_info(pred_suc_info* dst,pred_suc_info* src);
    void hton_pred_suc_info(pred_suc_info* dst,pred_suc_info* src);
    bool inRange(byte* key,byte* from, byte* to, bool from_inc, bool to_inc);
public:
	bool verifyChecksum(ip* header);
	void addChecksum(ip* header);

	bool findSuccessor(byte* thekey,DHTNodeInfo whotoask, bool timed=0);

	bool sendDHTUpdate(bool added, bool init=0);

	static void* updateFingerHelper(void* arg);
	struct updateFingerHelperParameter{
		PacketParser* pp;
		int n;
	};

	static void* fetchDataHelper(void* arg);

private:
		void hexDump(Frame frame);
		bool dumpEthernet(Frame frame);
		bool dumpIPv4(Frame frame);
		//static bool dumpARP(Frame frame);
		//static bool dumpTCP(Frame frame);
		bool dumpUDP(Frame frame);
		//static bool dumpICMP(Frame frame);

		bool dumpPacket(Frame frame,int interface,bool send);
		void dumpMAC(byte* mac);

};



#endif
