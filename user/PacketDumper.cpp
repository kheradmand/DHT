#include "PacketDumper.h"
#include "OstreamManip.h"
#include "common.h"
#include "sr_protocol.h"
#include "sm.h"
#include <iostream>
using namespace std;

void PacketDumper::dumpMAC(byte* mac){
	for (int i=0;i<ETHER_ADDR_LEN;i++){
		cout << HEXOUT(mac[i]);
		if (i!=ETHER_ADDR_LEN-1) cout << ":";
	}
 
}

bool PacketDumper::dumpPacket(Frame frame,int interface,bool send){
	//Frame frame(_frame.length,new byte[_frame.length]);
	//memcpy(frame.data,_frame.data,_frame.length);

	cout << bold(send ? cyan("Sending") : magenta("Received")) << " packet with length " << frame.length << " " << (send ? "to" : "from") << " interface " << interface << ":" << endl;
	cout << "\t";
	hexDump(frame);
	return dumpEthernet(frame);
}

bool PacketDumper::dumpEthernet(Frame frame){
	int hlen = sizeof(sr_ethernet_hdr);
	if ((int)frame.length<hlen)
		RETURN("too small ethernet frame",0);

	sr_ethernet_hdr* header = (sr_ethernet_hdr*)(frame.data);
	cout << bold(">Ethernet:") << endl;
	cout << "\tSource MAC address:\t\t";
	dumpMAC(header->ether_shost);
	//for (int i=0;i<ETHER_ADDR_LEN;i++)
	//	cout << hex << (uint32)header->ether_shost[i] << ":";
	cout << endl;
	cout << "\tDestination MAC address:\t";
	dumpMAC(header->ether_dhost);
	//for (int i=0;i<ETHER_ADDR_LEN;i++)
	//	cout << hex << (uint32)header->ether_dhost[i] << ":";
	cout << endl;
	
	uint16 ether_type = ntohs(header->ether_type);
	cout << "\tNext protocol hex:\t\t" << HEXOUT(ether_type) << endl;
	
	Frame payload = Frame(frame.length-hlen,frame.data+hlen);

	if (ether_type == ETHERTYPE_IP)
		return dumpIPv4(payload);
	else
		RETURN("unexpected network layer protocol",0);
	return 0;

}


//fix endianness
bool PacketDumper::dumpIPv4(Frame frame){
	int hlen = sizeof(ip);
	if ((int)frame.length < hlen){
		cout << yellow("frame length is ") << frame.length << " expected " << hlen << endl;
		RETURN("too small ip packet",0);
	}
	ip* header = (ip*)frame.data;
	//if (header->ip_tos != 4)
	//	RETURN("expected IPv4",0);
	
	if ((int)frame.length < ntohs(header->ip_len)){
		cout << yellow("frame length is ") << frame.length << " expected " << hlen << endl;
		RETURN("too small ip packet",0);
	}

	char from_ip[INET_ADDRSTRLEN],to_ip[INET_ADDRSTRLEN];
	ip_t ip_src = header->ip_src.s_addr;
	ip_t ip_dst = header->ip_dst.s_addr;
	inet_ntop(AF_INET,&ip_src,from_ip,sizeof(from_ip));
	inet_ntop(AF_INET,&ip_dst,to_ip,sizeof(to_ip));
	
	cout << bold(">IPv4:") << endl;
	cout << "\tSource IP Address:\t" << from_ip << endl;
	cout << "\tDestination IP Address:\t" << to_ip << endl;
	cout << "\tNext protocol hex:\t" << HEXOUT(header->ip_p) << endl;

	Frame payload = Frame(frame.length-hlen,frame.data+hlen);
	if (header->ip_p == IPPROTO_UDP)
		return dumpUDP(payload);
	else {
		RETURN("unsupported protocol number",1);
	}
	return 0;


}

bool PacketDumper::dumpUDP(Frame frame){
	cout << bold(">UDP") << endl;
	sr_udp* header = (sr_udp*) frame.data;
	uint16 src = ntohs(header->port_src);
	uint16 dst = ntohs(header->port_dst);
	cout << "\tSource port number:\t\t" << (uint32)src << endl;
	cout << "\tDestination port number:\t" << (uint32)dst << endl;
	return 1;
}



void PacketDumper::hexDump(Frame frame){
	for (int i=0;i<(int)frame.length;i++){
		//cout << hex << (uint32_t)frame.data[i] << dec << " ";
		cout << HEXOUT(frame.data[i]) << " ";
		if (i%12==11) {cout << endl; cout << "\t";}//printf("%h ",frame.data[i]);
	}
	cout << endl;
}
