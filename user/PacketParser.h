#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "frame.h"
#include "sr_protocol.h"
#include "DHTNodeInfo.h"
using namespace std;

class SimulatedMachine;

class PacketParser{
private:

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
    
    pred_suc_info* delete_update_info;

    //pthread_t updateFinger_thread;

    
public:
    SimulatedMachine* sm;
	PacketParser(SimulatedMachine* _sm);
	bool parseFrame(Frame frame);
private:
	bool parseIPv4(Frame frame);
    bool parseUDP(Frame frame);
    bool parseDHT(Frame frame);
    bool parseDHTFindSuccessor(Frame frame);
    bool parseDHTUpdate(Frame frame);
    bool parseDHTTransfer(Frame frame);
    bool parseDHTDNS(Frame frame);

    void fillDefaultDHTHeader(dht_hdr* header, bool me=0);
    bool sendDHTFindSuccessorResponse(pred_suc_info my_pred_suc);
    bool sendDHTFindSuccessorQuery(DHTNodeInfo target,bool init=0,byte* thekey=NULL);

    //bool sendDHTTransferACK();

    bool sendDHTDNSResponse(Frame frame);


    bool sendDHTPacket(Frame frame, ip_t target_ip, port_t taget_port);
    bool sendFrame(Frame frame);



    byte* getFingerStart(int index);




    void ntoh_pred_suc_info(pred_suc_info* dst,pred_suc_info* src);
    void hton_pred_suc_info(pred_suc_info* dst,pred_suc_info* src);
    bool inRange(byte* key,byte* from, byte* to, bool from_inc, bool to_inc);
public:
    bool sendDHTTransferQuery();

    bool DNSQuery(string& k);
    bool sendDHTDNSSet(string& k, ip_t v);

    bool sendDHTTransfer(bool fromMetoSuc=0);
    void updateFinger(uint32 n, bool deleted=0);

	bool verifyChecksum(ip* header);
	void addChecksum(ip* header);

	bool findSuccessor(byte* thekey,DHTNodeInfo whotoask, bool timed=0);

	bool sendDHTUpdate(bool added, bool init=0);


	struct updateFingerHelperParameter{
		PacketParser* pp;
		int n;
	};



private:
		void hexDump(Frame frame);
		bool dumpEthernet(Frame frame);
		bool dumpIPv4(Frame frame);
		//static bool dumpARP(Frame frame);
		//static bool dumpTCP(Frame frame);
		bool dumpUDP(Frame frame);
		//static bool dumpICMP(Frame frame);
		bool dumpDHT(Frame frame);

		bool dumpPacket(Frame frame,int interface,bool send);
		void dumpMAC(byte* mac);

};

struct dns_record
{
    uint32_t ip;    /* Ip */
    uint8_t len;    /* Domain name length */
};

#endif
