#include "DHTNodeInfo.h"

#include <openssl/sha.h>


DHTNodeInfo::DHTNodeInfo(ip_t _ip,port_t _port){
	update(_ip, _port);
}

DHTNodeInfo::DHTNodeInfo(){
	update(0, 0);
}

void DHTNodeInfo::update(ip_t _ip,port_t _port){
	ip = _ip;
	port = _port;
	SHA1((unsigned char*)(&ip), DHT_KEY_SIZE, (unsigned char*)key);
}
