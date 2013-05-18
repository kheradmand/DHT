
#ifndef PACKET_DUMPER_H
#define PACKET_DUMPER_H

#include "frame.h"


class SimulatedMachine;

class PacketDumper{
private:
	static void hexDump(Frame frame);
	static bool dumpEthernet(Frame frame);
	static bool dumpIPv4(Frame frame);
	//static bool dumpARP(Frame frame);
	//static bool dumpTCP(Frame frame);
	static bool dumpUDP(Frame frame);
	//static bool dumpICMP(Frame frame);
	
public:
	static SimulatedMachine* sm;
	static bool dumpPacket(Frame frame,int interface,bool send);
	static void dumpMAC(byte* mac);


};


#endif
