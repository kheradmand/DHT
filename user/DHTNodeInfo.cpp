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
	SHA1((unsigned char*)(&ip), sizeof(ip_t), (unsigned char*)key);
}

void DHTNodeInfo::print(){

	cout << "for ip " << ip << " pirt " << port << endl;
	dumpKey(key);

}

void DHTNodeInfo::dumpKey(byte* thekey){
	for (int i=0;i<DHT_KEY_SIZE;i++)
		cout << HEXOUT(thekey[i]) << " ";
	cout << endl;
}
