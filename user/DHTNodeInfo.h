#ifndef DHT_NODE_INFO_H
#define DHT_NODE_INFO_H

#include "common.h"

class DHTNodeInfo{
public:
	DHTNodeInfo(ip_t _ip,port_t _port);
	DHTNodeInfo();
	void update(ip_t _ip,port_t _port);
	void print();
	static void dumpKey(byte* thekey);
	ip_t ip;
	port_t port;
	byte key[DHT_KEY_SIZE];
};


#endif
