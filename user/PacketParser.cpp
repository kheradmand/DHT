#include "PacketParser.h"
#include "common.h"
#include "sr_protocol.h"
#include "sm.h"

#include <iostream>
#include <cmath>
#include <map>
#include <sys/time.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <errno.h>
using namespace std;

PacketParser::PacketParser(SimulatedMachine* _sm){
	sm = _sm;
}



bool PacketParser::parseFrame(Frame frame){

	LO
	dumpPacket(frame, GATEWAY_IFACE, 0);
	ULO
	int hlen = sizeof(sr_ethernet_hdr);
	sr_ethernet_hdr* header = (sr_ethernet_hdr*)(frame.data);
	uint16 ether_type = ntohs(header->ether_type);
	Frame payload = Frame(frame.length-hlen,frame.data+hlen);
	if (ether_type == ETHERTYPE_IP){
		return parseIPv4(payload);
	}else {
		RETURN("expected ipv4 protocol, discarding packet",0);
	}
	return 0;
}





bool PacketParser::parseIPv4(Frame frame){
	WARNING("parsing ip");
	ip* ip_header = (ip*)frame.data;

	if (!verifyChecksum(ip_header)){
		RETURN("checksum not verified, discarding packet",0)
	}
	ip_src = ntohl(ip_header->ip_src.s_addr);
	ip_dst = ntohl(ip_header->ip_dst.s_addr);
	if (ip_dst != sm->me.ip){
		LO cout << "my ip is " << ip_dst << " gateway ip is" << sm->getInterfaceIP(GATEWAY_IFACE) << " " << sm->me.ip <<  endl; ULO
		RETURN("packet is not for me, discarding packet",0)
	}
	if (ip_header->ip_p != IPPROTO_UDP){
		RETURN("expected UDP protocol, discarding packet",0)
	}


    return parseUDP(Frame(frame.length-sizeof(ip),frame.data+sizeof(ip)));
}

bool PacketParser::parseUDP(Frame frame){
	WARNING("parsing udp");

    sr_udp* udp_header = (sr_udp*)(frame.data);
    port_src = ntohs(udp_header->port_src);
    port_dst = ntohs(udp_header->port_dst);
    if (port_dst != sm->me.port)
        RETURN("unexpected port number, discarding packet",0)

    return parseDHT(Frame(frame.length-sizeof(sr_udp), frame.data+sizeof(sr_udp)));

}

bool PacketParser::parseDHT(Frame frame){
    WARNING("parsing dht")
    
    dht_hdr* dht_header = (dht_hdr*)(frame.data);
    init_ip = ntohl(dht_header->init_ip.s_addr);
    init_port = ntohs(dht_header->init_port);
    key = dht_header->key;
    control = ntohs(dht_header->control);
    flags = control >> 8;
    operation = (byte)(control & DHT_OPER_MASK);
    N = ntohl(dht_header->n);
    

    Frame payload(frame.length-sizeof(dht_hdr), frame.data+sizeof(dht_hdr));
    
    
    
    switch (operation) {
        case DHT_OPER_FIND_SUCC:
        	return parseDHTFindSuccessor(payload);
            break;
        case DHT_OPER_UPDATE:
        	sm->perceivedN = N;
            return parseDHTUpdate(payload);
            break;
        case DHT_OPER_TRANSF:
            return parseDHTTransfer(payload);
            break;
        case DHT_OPER_DNS:
        	return parseDHTDNS(payload);
            break;
        default:
            RETURN("unexpected DHT operation",0);
            break;
    }

    return 0;
}

bool PacketParser::parseDHTFindSuccessor(Frame frame){
	cout << "received find successor packet" << endl;
	if (control & DHT_QUERY){ //FIND_SUCC Query
		LO cout << "find suc query" << endl; ULO;
		if (!sm->get_inNetwork())
			RETURN("Node is not in DHT network but received FIND_SUCCESSOR Query, discarding",0);
		if (inRange(key, sm->predecessor.key, sm->me.key, E, I)){
			//I am the successor! pred=my pre suc=me
			LO cout << "iam answer" << endl; ULO
			pred_suc_info response;
			response.pred.ip.s_addr = sm->predecessor.ip;
			response.pred.port = sm->predecessor.port;
			response.suc.ip.s_addr = sm->me.ip;
			response.suc.port = sm->me.port;
			return sendDHTFindSuccessorResponse(response);
		}else{
			LO cout << "iam not answer :(" << endl; ULO
			for (int i=sm->finger.size()-1;i>=0;i--)
				if (inRange(sm->finger[i].key, sm->me.key, key, E, E)){
					LO cout << "forwarding query to finger" << i << endl; ULO
					return sendDHTFindSuccessorQuery(sm->finger[i]);
				}
			WARNING("found no finger");
			cout << "perceivedN" << sm->perceivedN << endl;
			if (sm->perceivedN == 1){
				WARNING("there is only me, so i should be the successor");
				pred_suc_info response;
				response.pred.ip.s_addr = sm->predecessor.ip;
				response.pred.port = sm->predecessor.port;
				response.suc.ip.s_addr = sm->me.ip;
				response.suc.port = sm->me.port;
				return sendDHTFindSuccessorResponse(response);
			}else{
				WARNING("forwarding")
				return sendDHTFindSuccessorQuery(sm->successor);
			}
		}

	}else{  //FIND_SUCC Ans
		WARNING("received find suc response")
		if (init_ip != sm->me.ip)
			RETURN("received find successor response, but its not for me!",0);

		//signal mikonim, thread ha mibinan age key e morede nazareshoon bood bar midaran
		WARNING("locking find suc");
		LOCK(sm->findSuc_lock);
		pred_suc_info* ans = (pred_suc_info*)frame.data;
		ntoh_pred_suc_info(&(sm->find_suc_ans),ans);
		sm->find_suc_N = N;
		memcpy(sm->find_suc_key, key, DHT_KEY_SIZE);
		pthread_cond_broadcast(&sm->findSuc_cond);
		UNLOCK(sm->findSuc_lock);
		WARNING("unloking find succ");
		return 1;
	}
	return 0;

}

bool PacketParser::parseDHTUpdate(Frame frame){
	if (control & DHT_ADDED){
		if (init_ip == sm->me.ip){
			WARNING("add update packet circled successfully");
			//ehtemalan hame kara ghablan shode :-?
			//finger haye khodesho peida kone
			//elaat ro az suc begire
			//in network hesab she
			LOCK(sm->inNetwork_lock);
			//sm->inNetwork = 1; //in kari vaghti eleati az baghali gerefim anjam midim!
			pthread_cond_signal(&sm->inNetwork_cond);
			UNLOCK(sm->inNetwork_lock);
			return 1;
		}else{
			LO cout << "N in updating is " << N  << endl; ULO
			//check if pred
			if (N == 2 || inRange(key, sm->predecessor.key, sm->me.key, E, E))
				sm->predecessor.update(init_ip,init_port);
			//check if suc
			if (N == 2 || inRange(key, sm->me.key, sm->successor.key, E, E))
				sm->successor.update(init_ip,init_port);

			//updateFingerHelperParameter param;
			//param.pp = this;
			//param.n = N;
			//int rc = pthread_create(&updateFinger_thread, &sm->attr, updateFingerHelper, (void*)(&param));
			//if (rc)
			//	RETURN("failed creating new thread",0);
			updateFinger(N);

			return sendDHTUpdate(1);
		}
	}else{ //deleted
		WARNING("received delete update")
		delete_update_info = (pred_suc_info*)(frame.data);
		if (init_ip == sm->me.ip){
			WARNING("delete update packet circled successfully")
			//elaat ro enteghal dade ghalan
			//hala az in network kharej mishe;
			LOCK(sm->inNetwork_lock);
			sm->inNetwork = 0;
			pthread_cond_signal(&sm->inNetwork_cond);
			UNLOCK(sm->inNetwork_lock);
			return 1;
		}else{
			pred_suc_info pred_suc;
			ntoh_pred_suc_info(&pred_suc, (pred_suc_info*)frame.data);


			sendDHTUpdate(0);

			//check if pred
			if (N==1 || inRange(key, sm->predecessor.key, sm->me.key, I, E)){
				ERROR("need to change pred")
				sm->predecessor.update(pred_suc.pred.ip.s_addr, pred_suc.pred.port);
			}
			//check if suc
			if (N==1 || inRange(key, sm->me.key, sm->successor.key, E, I)){
				ERROR("nedd to change suc")
				sm->successor.update(pred_suc.suc.ip.s_addr, pred_suc.suc.port);
			}

			//updateFingerHelperParameter param;
			//param.pp = this;
			//param.n = N;
			//int rc = pthread_create(&updateFinger_thread, &sm->attr, updateFingerHelper, (void*)(&param));
			//if (rc)
			//	RETURN("failed creating new thread",0)
			updateFinger(N, 1);

			return 1;
		}
	}
	return 0;
}

bool PacketParser::parseDHTTransfer(Frame frame){

	WARNING("received DHT bulk Transfer");
	/*if (control & DHT_ACK){
		WARNING("received ack")
		LOCK(sm->ack_lock);
		pthread_cond_signal(&sm->ack_cond);
		UNLOCK(sm->ack_lock)
		return 1;
	}else*/ if (control & DHT_QUERY){
		WARNING("query for trasfer information");

		//LOCK(sm->ack_lock);
//				int rc;
//				do{
//					timeval now;
//					gettimeofday(&now, NULL);
//					timespec t;
//					t.tv_sec = now.tv_sec + WAIT_TIME;
//					t.tv_nsec = 0;
//					parser.sendDHTTransfer(1);
//					LO cout << "wating for ack" << endl; ULO
//					rc = pthread_cond_timedwait(&sm->ack_cond, &sm->ack_lock, &t);
//				}while( rc == 60);
		sendDHTTransfer();
		//pthread_cond_wait(&sm->ack_cond, &sm->ack_lock);
		//UNLOCK(sm->ack_lock);
		return 1;

	}else{
		WARNING("inforrmation to store")
		byte* ptr = frame.data;

		uint8_t count = *ptr;
		ptr++;
		LO cout << "count is " << (int)count << endl; ULO
		for(uint i = 0; i < count; i++){
			dns_record* record = (dns_record*) ptr;
			uint32_t ip = ntohl(record->ip);

			uint8_t len = record->len;
			char buf[256];
			memcpy(buf, ptr + sizeof(dns_record), len);

			string domain(buf);
			LO cout << "adding len " << (int)len << "\"" << domain << "\" " << ip << endl; ULO
			sm->dnsChache[domain] = ip;

			ptr += sizeof(dns_record) + len;
		}

		//sendDHTTransferACK();

		LOCK(sm->transfer_lock);
		pthread_cond_signal(&sm->transfer_cond);
		UNLOCK(sm->transfer_lock)

		return 1;
	}
}


bool PacketParser::parseDHTDNS(Frame frame){
	WARNING("parsing DHT dns")
	if (control & DHT_GET){ //get

		if (control & DHT_QUERY){
			WARNING("dns get query")
			return sendDHTDNSResponse(frame);
		}else{
			WARNING("dns get response")
			if (frame.length == 0){
				ERROR("name not found")
				sm->dns_found = 0;
			}else{
				WARNING("found some answer for dns query")
				sm->dns_found = 1;
				uint32* ans = (uint32*)frame.data;
				sm->dns_ans = ntohl(*ans);
			}
			LOCK(sm->dns_lock);
			pthread_cond_signal(&sm->dns_cond);
			UNLOCK(sm->dns_lock);
			return 1;
		}
	}else{ //set
		WARNING("dns set")
		dns_record* record = (dns_record*) frame.data;
		uint32_t ip = ntohl(record->ip);

		uint8_t len = record->len;
		char buf[256];
		memcpy(buf, frame.data + sizeof(dns_record), len);

		string domain(buf);
		LO cout << "adding " << domain << " " << ip << endl; ULO
		sm->dnsChache[domain] = ip;
		return 1;
	}
	return 0;
}

void PacketParser::fillDefaultDHTHeader(dht_hdr* header,bool me){
	byte dummy[DHT_KEY_SIZE];
	if (!key)
		key = dummy;
	header->init_ip.s_addr = htonl(me ? sm->me.ip : init_ip);
	header->init_port = htons(me ? sm->me.port : init_port);
	memcpy(header->key, (me ? sm->me.key : key), DHT_KEY_SIZE);
	header->n = htonl(sm->perceivedN);
}

bool PacketParser::sendDHTFindSuccessorResponse(pred_suc_info my_pred_suc){
	byte payload[sizeof(dht_hdr)+sizeof(pred_suc_info)];
	Frame frame(sizeof(payload),payload);

	dht_hdr* dht_header = (dht_hdr*)payload;
	pred_suc_info* pred_suc = (pred_suc_info*)(payload+sizeof(dht_hdr));
	hton_pred_suc_info(pred_suc, &my_pred_suc);

	fillDefaultDHTHeader(dht_header);
	dht_header->control = htons(DHT_OPER_FIND_SUCC); //flagesh alan roo answer hast


	return sendDHTPacket(frame, init_ip, init_port);
}

bool PacketParser::sendDHTFindSuccessorQuery(DHTNodeInfo target,bool init,byte* thekey){
	byte payload[sizeof(dht_hdr)];
	Frame frame(sizeof(payload),payload);

	dht_hdr* dht_header = (dht_hdr*)payload;

	dht_header->control = htons(DHT_OPER_FIND_SUCC | DHT_QUERY);

	if (init){
		dht_header->init_ip.s_addr = htonl(sm->me.ip);
		dht_header->init_port = htons(sm->me.port);
		memcpy(dht_header->key, thekey, DHT_KEY_SIZE);
	}else
		fillDefaultDHTHeader(dht_header);

	return sendDHTPacket(frame, target.ip, target.port);
}

bool PacketParser::sendDHTUpdate(bool added, bool init){
	byte payload[sizeof(dht_hdr)+(added? 0 : sizeof(pred_suc_info))];
	Frame frame(sizeof(payload),payload);

	dht_hdr* dht_header = (dht_hdr*)payload;
	pred_suc_info* next;
	if (!added){
		next = (pred_suc_info*)(payload+sizeof(dht_hdr));
		if (init){
			pred_suc_info info;
			info.pred.ip.s_addr = sm->predecessor.ip;
			info.suc.ip.s_addr = sm->successor.ip;
			info.pred.port = sm->predecessor.port;
			info.suc.port = sm->successor.port;
			hton_pred_suc_info(next, &info);
		}else{
			memcpy(next, delete_update_info, sizeof(pred_suc_info));
		}
	}

	fillDefaultDHTHeader(dht_header, init);
	dht_header->control = htons(DHT_OPER_UPDATE | (added? DHT_ADDED : 0));

//	if (init){
//		fillDefaultDHTHeader(dht_header, 1);
//		dht_header->init_ip.s_addr = htonl(sm->me.ip);
//		dht_header->init_port = htons(sm->me.port);
//		memcpy(dht_header->key, sm->me.key, DHT_KEY_SIZE);
//	}

	return sendDHTPacket(frame, sm->predecessor.ip, sm->predecessor.port);
}


bool PacketParser::sendDHTTransfer(bool fromMetoSuc){
	ERROR("want to bult transfer information (send dht transfer)");
	vector<string> transfers;

	byte temp[DHT_KEY_SIZE];
	for (typeof(sm->dnsChache.begin()) i=sm->dnsChache.begin(); i!=sm->dnsChache.end();i++){
		SHA1((unsigned char*)i->first.c_str(), i->first.length(), (unsigned char*)temp);
		if (fromMetoSuc || inRange(temp, sm->predecessor.key, key, E, I)) //chon hanooz pred update nashode prede man dar vaghe prede tarafe!
			transfers.push_back(i->first);
	}

	int size = 1;

	LO
	cout << "transfers:" << endl;
	for(uint i = 0; i < transfers.size(); i++){
		cout << "will transfer " << transfers[i] << endl;
		size += transfers[i].length() + 1 + sizeof(dns_record);
	}
	ULO

	byte payload[sizeof(dht_hdr)+ size];
	Frame frame(sizeof(payload),payload);

	dht_hdr* dht_header = (dht_hdr*)payload;
//	dht_header->init_ip.s_addr = htonl(sm->me.ip);
//	dht_header->init_port = htons(sm->me.port);
//	memcpy(dht_header->key, sm->me.key, DHT_KEY_SIZE);
	fillDefaultDHTHeader(dht_header, 1);
	dht_header->control = htons(DHT_OPER_TRANSF); //DHT_QUERy nist => asnwere

	byte* ptr = payload + sizeof(dht_hdr);

	// store number of records
	uint8_t length = transfers.size();
	*(ptr) = length;
	ptr++;

	for(uint i = 0; i < transfers.size(); i++){
		dns_record* record = (dns_record*) ptr;
		record->ip = htonl(sm->dnsChache[transfers[i]]);
		record->len = transfers[i].length() + 1;
		memcpy(ptr + sizeof(dns_record), transfers[i].c_str(), transfers[i].length());
		*(ptr + sizeof(dns_record) + transfers[i].length()) = '\0';
		ptr += sizeof(dns_record) + transfers[i].length() + 1;
	}

	//return sendDHTPacket(frame, sm->predecessor.ip, sm->predecessor.port);
	sendDHTPacket(frame, (fromMetoSuc? sm->successor.ip : init_ip), (fromMetoSuc? sm->successor.port : init_port));

	for (uint i=0;i<transfers.size();i++)
		sm->dnsChache.erase(transfers[i]);

	return 1;

}

bool PacketParser::sendDHTDNSSet(string& k, ip_t v){
	ERROR("want to set key on somewhere");

	byte sha[DHT_KEY_SIZE];
	SHA1((unsigned char*)k.c_str(), k.length(), (unsigned char*)sha);

	if (sm->perceivedN>1){
		findSuccessor(sha, sm->successor, 0);
		LO cout << "succesor for record found " << endl; ULO
		UNLOCK(sm->findSuc_lock);
	}

	if (sm->perceivedN<2 || sm->find_suc_ans.suc.ip.s_addr == sm->me.ip){
		LO cout << "i am the owner of key no need to ask anybody in dns set -----" << endl; ULO
		sm->dnsChache[k] = v;
		return 1;
	}

	ERROR("should save key remotely");
	LO cout << "size of dns record is" << sizeof(dns_record) << endl; ULO
	int size = k.length()+1+sizeof(dns_record)+1;

	byte payload[sizeof(dht_hdr)+ size];
	Frame frame(sizeof(payload),payload);

	dht_hdr* dht_header = (dht_hdr*)payload;
//	dht_header->init_ip.s_addr = htonl(sm->me.ip);
//	dht_header->init_port = htons(sm->me.port);
//	memcpy(dht_header->key, sm->me.key, DHT_KEY_SIZE);
	fillDefaultDHTHeader(dht_header, 1);
	dht_header->control = htons(DHT_OPER_TRANSF); //DHT_QUERy nist => asnwere

	byte* ptr = payload + sizeof(dht_hdr);
	*ptr = 1;
	ptr++;
	dns_record* record = (dns_record*) (ptr);
	record->ip = htonl(v);
	record->len = k.length() + 1;
	memcpy(ptr + sizeof(dns_record), k.c_str(), k.length());
	*(ptr + sizeof(dns_record) + k.length()) = '\0';




	//return sendDHTPacket(frame, sm->predecessor.ip, sm->predecessor.port);
	return sendDHTPacket(frame, sm->find_suc_ans.suc.ip.s_addr , sm->find_suc_ans.suc.port);
}



//bool PacketParser::sendDHTTransferACK(){
//	byte payload[sizeof(dht_hdr)];
//	Frame frame(sizeof(payload),payload);
//
//	dht_hdr* dht_header = (dht_hdr*)payload;
//	fillDefaultDHTHeader(dht_header);
//	dht_header->control = htons(DHT_OPER_TRANSF | DHT_ACK);
//	return sendDHTPacket(frame, init_ip, init_port);
//}


bool PacketParser::sendDHTTransferQuery(){
	byte payload[sizeof(dht_hdr)];
	Frame frame(sizeof(payload),payload);

	dht_hdr* dht_header = (dht_hdr*)payload;
//	dht_header->init_ip.s_addr = htonl(sm->me.ip);
//	dht_header->init_port = htons(sm->me.port);
//	dht_header->n = htonl(sm->perceivedN);
//	memcpy(dht_header->key, sm->me.key, DHT_KEY_SIZE);
	fillDefaultDHTHeader(dht_header, 1);
	dht_header->control = htons(DHT_OPER_TRANSF | DHT_QUERY);

	return sendDHTPacket(frame, sm->successor.ip, sm->successor.port);

}

bool PacketParser::sendDHTDNSResponse(Frame frame){
	uint8_t len = *((byte*)frame.data);
	char buf[256];
	memcpy(buf, frame.data + sizeof(byte), len);
	string domain(buf);
	LO cout << "query is for  len" << (int)len << " \"" << domain << "\"" << endl; ULO

	if (sm->dnsChache.find(domain) == sm->dnsChache.end()){
		ERROR("not found")
		byte payload[sizeof(dht_hdr)];
		Frame frame(sizeof(payload),payload);
		dht_hdr* dht_header = (dht_hdr*)payload;
		fillDefaultDHTHeader(dht_header, 1);
		dht_header->control = htons(DHT_OPER_DNS | DHT_GET); //dht get response
		return sendDHTPacket(frame, init_ip, init_port);
	}else{
		ERROR("found") LO cout << " it is " << sm->dnsChache[domain] << endl; ULO
		byte payload[sizeof(dht_hdr)+sizeof(ip_t)];
		Frame frame(sizeof(payload),payload);
		dht_hdr* dht_header = (dht_hdr*)payload;
		fillDefaultDHTHeader(dht_header, 1);
		dht_header->control = htons(DHT_OPER_DNS | DHT_GET); //dht get response
		ip_t* ans = (ip_t*)(payload+sizeof(dht_hdr));
		*ans = htonl(sm->dnsChache[domain]);
		return sendDHTPacket(frame, init_ip, init_port);
	}

}

bool PacketParser::DNSQuery(string& k){
	LO cout << "want to send a dns query for " << k << endl; ULO
	byte sha[DHT_KEY_SIZE];
	SHA1((unsigned char*)k.c_str(), k.length(), (unsigned char*)sha);

	if (sm->perceivedN>1){
		findSuccessor(sha, sm->successor, 0);
		LO cout << "succesor for record found " << endl; ULO
		UNLOCK(sm->findSuc_lock);
	}

	if (sm->perceivedN<2 || sm->find_suc_ans.suc.ip.s_addr == sm->me.ip){
		LO cout << magenta("i am the owner of key no need to ask anybody") << endl; ULO
		if (sm->dnsChache.find(k)==sm->dnsChache.end())
			sm->dns_found = 0;
		else{
			sm->dns_found = 1;
			sm->dns_ans = sm->dnsChache[k];
		}
		return 1;
	}

	byte payload[sizeof(dht_hdr)+2*sizeof(byte)+k.length()];
	Frame frame(sizeof(payload),payload);
	dht_hdr* dht_header = (dht_hdr*)payload;
	fillDefaultDHTHeader(dht_header, 1);
	dht_header->control = htons(DHT_OPER_DNS | DHT_GET | DHT_QUERY); //dns get query

	byte* len = (byte*)(payload+sizeof(dht_hdr));
	*len = k.length()+1; //baraye null
	memcpy(len+sizeof(byte), k.c_str(), k.length());
	*(len+sizeof(byte)+k.length()) = '\0';
	LO
	cout << "coded packet is :";
	for (int i=0;i<(int)k.length();i++)
		cout << (char)len[i+1];
	cout << endl;
	ULO


	LOCK(sm->dns_lock);
	while(1){
		LO cout << "sending dns query packet " << endl; ULO
		sendDHTPacket(frame, sm->find_suc_ans.suc.ip.s_addr , sm->find_suc_ans.suc.port);

		timeval now;
		gettimeofday(&now, NULL);
		timespec t;
		t.tv_sec = now.tv_sec + WAIT_TIME*2;
		t.tv_nsec = 0;

		LO cout << "conditional timed wait for dns response" << endl; ULO
		int rc = pthread_cond_timedwait(&sm->dns_cond, &sm->dns_lock, &t);
		if (rc == EINVAL) {ERROR("dns ival, retry"); continue;}
		if (rc == ETIMEDOUT) {ERROR("dns timeout, retry"); continue;}
		break;
	}
	UNLOCK(sm->dns_lock);

	return 1;


}

bool PacketParser::sendDHTPacket(Frame frame, ip_t target_ip, port_t target_port){
	byte payload[sizeof(sr_ethernet_hdr)+sizeof(ip)+sizeof(sr_udp)+frame.length];
	Frame packet(sizeof(payload),payload);

	sr_ethernet_hdr* ether_header = (sr_ethernet_hdr*)payload;
	ip* ip_header = (ip*)(payload+sizeof(sr_ethernet_hdr));
	sr_udp* udp_header = (sr_udp*)(payload+sizeof(sr_ethernet_hdr)+sizeof(ip));
	dht_hdr* dht_header = (dht_hdr*)(payload+sizeof(sr_ethernet_hdr)+sizeof(ip)+sizeof(sr_udp));

	LO cout << "vaaaa inja alan gateway mac ine "; ULO
	dumpMAC(sm->getGatewayMAC());
	memcpy(ether_header->ether_shost, sm->getInterfaceMAC(GATEWAY_IFACE), ETHER_ADDR_LEN);
	memcpy(ether_header->ether_dhost, sm->getGatewayMAC(), ETHER_ADDR_LEN);
	ether_header->ether_type = htons(ETHERTYPE_IP);


	memset(ip_header, 0, sizeof(ip));
	ip_header->ip_v = 4;
	ip_header->ip_hl = 5;
	ip_header->ip_len = htons(packet.length-sizeof(sr_ethernet_hdr));
	ip_header->ip_ttl = 255;
	ip_header->ip_p = IPPROTO_UDP;
	ip_header->ip_src.s_addr = htonl(sm->me.ip);
	ip_header->ip_dst.s_addr = htonl(target_ip);
	addChecksum(ip_header);

	memset(udp_header, 0, sizeof(sr_udp));
	udp_header->port_src = htons(sm->me.port);
	udp_header->port_dst = htons(target_port);
	udp_header->length = htons(sizeof(sr_udp)+frame.length);

	memcpy(dht_header, frame.data, frame.length);



	//packet is ready to send
	LOCK(sm->send_lock);
	bool ret = sendFrame(packet);
	UNLOCK(sm->send_lock);
	if (!ret)
		RETURN("failed sending packet",0);

	return ret;
}

bool PacketParser::sendFrame(Frame frame){
	int c = 100;
	LO
	dumpPacket(frame, GATEWAY_IFACE, 1);
	ULO

	while (c-- && !sm->sendFrame(frame, GATEWAY_IFACE));
	if (c>=0){
		LO cout << green("packet sent successfully") << endl; ULO
		return 1;
	}else{
		LO cout << red("packet send failed") << endl; ULO
		return 0;

	}
}

void PacketParser::ntoh_pred_suc_info(pred_suc_info* dst,pred_suc_info* src){
	dst->suc.ip.s_addr = ntohl(src->suc.ip.s_addr);
	dst->pred.ip.s_addr = ntohl(src->pred.ip.s_addr);
	dst->suc.port = ntohs(src->suc.port);
	dst->pred.port = ntohs(src->pred.port);
}
void PacketParser::hton_pred_suc_info(pred_suc_info* dst,pred_suc_info* src){
	dst->suc.ip.s_addr = htonl(src->suc.ip.s_addr);
	dst->pred.ip.s_addr = htonl(src->pred.ip.s_addr);
	dst->suc.port = htons(src->suc.port);
	dst->pred.port = htons(src->pred.port);
}

bool PacketParser::inRange(byte* key,byte* from, byte* to, bool from_inc, bool to_inc){
	//khob  inja chon ghazie kharkheshie ye meghdar moshkelat dare
	//avalin moshkel ine ke vaghti ke saro tahe baze yekie maloom nis khalie manzoor ya kol, farz mikonim manzoor pore
	int ft = memcmp(from, to, DHT_KEY_SIZE);
	int comp = memcmp(key, from, DHT_KEY_SIZE);

	LO
	cout << "checking in range" << endl;
//	DHTNodeInfo::dumpKey(key);
//	DHTNodeInfo::dumpKey(from);
//	DHTNodeInfo::dumpKey(to);
//	cout << "ft " << ft << " cmop " << comp << endl;
	ULO

	if (ft == 0){ //kolle baze
		if (!from_inc && !to_inc && comp == 0)
			return 0;
		else
			return 1;
	}

	if (ft>0)
		return !(inRange(key, to, from, !to_inc, !from_inc));

	//ft > 0


	if (comp<0 || (comp==0 && !from_inc))
		return 0;
	comp = (memcmp(key, to, DHT_KEY_SIZE));
	if (comp>0 || (comp==0 && !to_inc))
		return 0;
	return  1;
}



byte* PacketParser::getFingerStart(int index){
	static byte ret[DHT_KEY_SIZE];
	memcpy(ret, sm->me.key, DHT_KEY_SIZE);
	int byteIndex = index/8;
	index%=8;
	uint16 res (1<<index);
	while (res && DHT_KEY_SIZE-1-byteIndex>=0){
		res+=ret[DHT_KEY_SIZE-1-byteIndex];
		ret[DHT_KEY_SIZE-1-byteIndex] = res % 256;
		res/=256;
		byteIndex++;
	}
	return ret;

}
//
//void* PacketParser::updateFingerHelper(void* arg){
//	updateFingerHelperParameter* param = (updateFingerHelperParameter*)arg;
//	param->pp->updateFinger(param->n);
//	return NULL;
//}


void PacketParser::updateFinger(uint32 n, bool deleted){
	ERROR("started to update finger!")
	LO cout << "N is " << n << endl; ULO
	if (n == 0){
		return;
	}
	int m = log2((double)n);
	LO cout << "aakala " << sm->finger.size() << endl; ULO
	int lastSize = sm->finger.size();
	sm->finger.resize(m+1);
	sm->finger[0].update(sm->successor.ip, sm->successor.port);

	if (n==1){
		for (int i=0;i<(int)sm->finger.size();i++)
			sm->finger[i].update(sm->me.ip, sm->me.port);
		//pthread_exit(NULL);
		return;
	}

	int mn = min(m, lastSize);
	LO cout << " mn " << mn << " m " << m  << "!" << endl; ULO
	for (int i=0;i<mn-1;i++){
		LO cout << "kkkkkkkkkkkk" << endl; ULO
		if (inRange(getFingerStart(i+1), sm->me.key, sm->finger[i].key, I, E) &&
				(!deleted || memcmp(sm->finger[i].key, key/*kare khatarnakie!*/, DHT_KEY_SIZE)!=0)){
			LO cout << "figer " << i << " is aprop for " << i+1 << endl; ULO
			sm->finger[i+1].update(sm->finger[i].ip, sm->finger[i].port);
		}else{
			LO cout << "figer " << i << " is NOTOTOTOO aprop for " << i+1 << endl; ULO
			//bool ret = findSuccessor(getFingerStart(i+1), sm->successor);
			//if (!ret)
			//	ERROR("finding successor in finger update failed")
			//else
			while(!findSuccessor(getFingerStart(i+1), sm->successor)){
				UNLOCK(sm->findSuc_lock);
				ERROR("==========================================")
			}
			sm->finger[i+1].update(sm->find_suc_ans.suc.ip.s_addr, sm->find_suc_ans.suc.port);
			UNLOCK(sm->findSuc_lock);


		}
	}
	LO cout << "what the " << endl; ULO
	for (int i=mn;i<(int)sm->finger.size();i++){
		LO cout << "kkkkkasasasaskkkkkkk" << i << endl; cout << flush; ULO
		//bool ret = findSuccessor(getFingerStart(i), sm->successor);
		//if (!ret)
		//	ERROR("finding successor in finger update failed")
		//else
		while(!findSuccessor(getFingerStart(i), sm->successor)){
			UNLOCK(sm->findSuc_lock);
			ERROR("==========================================")
		}
		sm->finger[i].update(sm->find_suc_ans.suc.ip.s_addr, sm->find_suc_ans.suc.port);
		UNLOCK(sm->findSuc_lock);
	}
	ERROR("update finger finished")
	//pthread_exit(NULL);
}

//in tabe vaghti barmigarde findSuc_lock lock hastesh
bool PacketParser::findSuccessor(byte* thekey, DHTNodeInfo whotoask, bool timed){
	ERROR("staring find successor")
	LO cout << flush; ULO
	LOCK(sm->findSuc_lock)
	ERROR("locked find successor")
	LO cout << flush; ULO
	bool b = sendDHTFindSuccessorQuery(whotoask, 1, thekey);
	LO cout << "sendDHTFindSuccessorQuery returned with " << b << endl; cout << flush; ULO
	//DHTNodeInfo info(0,0);
	int rc;

	timeval now;
	gettimeofday(&now, NULL);
	timespec t;
	t.tv_sec = now.tv_sec + WAIT_TIME;
	t.tv_nsec = 0;

	bool cont = 1;
	do {
		ERROR("loop!")
		cont = 0;
		if (timed){
			LO cout << "sleeping timed" << endl; ULO
			rc = pthread_cond_timedwait(&sm->findSuc_cond, &sm->findSuc_lock, &t);
			LO cout << "wokeup timed" << endl; ULO
			LO cout << "rc after time wait is " << rc << endl; ULO
			if (rc == EINVAL) {cont=1; continue;}
			if (rc == ETIMEDOUT) {WARNING("timeout") break;}
			WARNING("first setting N "); LO cout << sm->perceivedN << endl; ULO
			sm->perceivedN = sm->find_suc_N;
		}else{
			LO cout << "sleeping unlimite" << endl; ULO
			rc = pthread_cond_wait(&sm->findSuc_cond, &sm->findSuc_lock);
			LO cout << "wokeup unlimite" << endl; ULO
			//rc = pthread_cond_timedwait(&sm->findSuc_cond, &sm->findSuc_lock, &t);
			//if (rc == 22) {cont=1; continue;}
			//if (rc == 60) {ERROR("timeout") break;}
		}
		//info.update(sm->find_suc_ans.suc.ip.s_addr,sm->find_suc_ans.suc.port);
	} while (cont || memcmp(thekey, sm->find_suc_key, DHT_KEY_SIZE)!=0);
	LO cout << "rc when returning is " << rc << endl; ULO;
	return (rc == 0);
}

bool PacketParser::verifyChecksum(ip* header){
	uint32 sum = 0;
	byte* arr = (byte*)(header);
	for (int i=0;i<(int)sizeof(ip);i+=2){
		uint16 add = arr[i];
		add<<=8;
		add+=arr[i+1];
		sum += add;
	}
	sum += sum>>16;
	sum = ~sum;
	if (sum & 0x0FFFF)
		return 0;
	return 1;
}

void PacketParser::addChecksum(ip* header){
	uint32 sum = 0;
	byte* arr = (byte*)(header);
	for (int i=0;i<(int)sizeof(ip);i+=2){
		uint16 add = arr[i];
		add<<=8;
		add+=arr[i+1];
		sum += add;
	}
	sum -= ntohs(header->ip_sum);
	sum += sum>>16;
	//cout << yellow("sum") << HEXOUT(sum) << endl;
	sum = ~sum;
	header->ip_sum = htons((uint16)sum);	
}



void PacketParser::dumpMAC(byte* mac){
	for (int i=0;i<ETHER_ADDR_LEN;i++){
		cout << HEXOUT(mac[i]);
		if (i!=ETHER_ADDR_LEN-1) cout << ":";
	}

}

bool PacketParser::dumpPacket(Frame frame,int interface,bool send){
	//Frame frame(_frame.length,new byte[_frame.length]);
	//memcpy(frame.data,_frame.data,_frame.length);

	cout << bold(send ? cyan("Sending") : magenta("Received")) << " packet with length " << frame.length << " " << (send ? "to" : "from") << " interface " << interface << ":" << endl;
	cout << "\t";
	hexDump(frame);
	return dumpEthernet(frame);
}

bool PacketParser::dumpEthernet(Frame frame){
	int hlen = sizeof(sr_ethernet_hdr);
	if ((int)frame.length<hlen)
		URETURN("too small ethernet frame",0);

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
		URETURN("unexpected network layer protocol",0);
	return 0;

}


//fix endianness
bool PacketParser::dumpIPv4(Frame frame){
	int hlen = sizeof(ip);
	if ((int)frame.length < hlen){
		cout << yellow("frame length is ") << frame.length << " expected " << hlen << endl;
		URETURN("too small ip packet",0);
	}
	ip* header = (ip*)frame.data;
	//if (header->ip_tos != 4)
	//	RETURN("expected IPv4",0);

	if ((int)frame.length < ntohs(header->ip_len)){
		cout << yellow("frame length is ") << frame.length << " expected " << ntohs(header->ip_len) << endl;
		URETURN("too small ip packet",0);
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
		URETURN("unsupported protocol number",1);
	}
	return 0;


}

bool PacketParser::dumpUDP(Frame frame){
	cout << bold(">UDP") << endl;
	sr_udp* header = (sr_udp*) frame.data;
	uint16 src = ntohs(header->port_src);
	uint16 dst = ntohs(header->port_dst);
	cout << "\tSource port number:\t\t" << (uint32)src << endl;
	cout << "\tDestination port number:\t" << (uint32)dst << endl;
	return dumpDHT(Frame(frame.length-sizeof(sr_udp), frame.data+sizeof(sr_udp)));
}

bool PacketParser::dumpDHT(Frame frame){
	cout << bold(">DHT") << endl;
	cout << "\t";
	hexDump(frame);
	dht_hdr* header = (dht_hdr*)frame.data;
	cout << "\tControl(hex):\t" << HEXOUT(ntohs(header->control)) << endl;
	//cout << "Operation(hex)\t:" << HEXOUT(operation) << endl;
	//cout << "Flags(hex):\t\t" << HEXOUT(flags) << endl;
	return 1;

}



void PacketParser::hexDump(Frame frame){
	for (int i=0;i<(int)frame.length;i++){
		//cout << hex << (uint32_t)frame.data[i] << dec << " ";
		cout << HEXOUT(frame.data[i]) << " ";
		if (i%12==11) {cout << endl; cout << "\t";}//printf("%h ",frame.data[i]);
	}
	cout << endl;
}



///*
// * bool PacketParser::parseDHTUpdate(Frame frame){
//	if (flags & DHT_ADDED){
//
//		dht_update_hdr* dht_update_header = (dht_update_hdr*)frame.data;
//		int size = ntohl(dht_update_header->size);
//		int couter = ntohl(dht_update_header->counter);
//		int base = ntohl(dht_update_header->base);
//		fin = (ip_port*)(frame.data+sizeof(dht_update_header));
//		if (init_ip == sm->getInterfaceIP(GATEWAY_IFACE)){
//			WARNING("add update packet circled succefully");
//
//			finger.resize(size);;
//			for (int i=0;i<size;i++){
//				finger[i].update(ntohl(fin[i].ip.in_addr), ntohs(fin[i].port));
//			}
//			// ODO: hala az baghali etelaat begir
//			return 1;
//		}
//		//check if pred
//		if (inRange(key, pred.key, me.key, E, E))
//			pred.update(init_ip,init_port);
//		//check if suc
//		if (inRange(key, me.key, suc.key, E, E))
//			succ.updadate(init_ip,init_port);
//
//		counter--;
//		if (couter == 0){
//			base *= 2;
//			counter = base;
//			//ODO: khodeto be list ezafe kon
//		}
//		//ODO:peigham ro be sucet befres
//
//
//
//
//
//
//
//
//
//		//update finger list
//		for (int i=0;i<(int)finger.size();i++)
//			if (inRange(key, (i==0 ? ))) //////////////////
//				/*
//	                     //if finger list should get bigger
//	                     int logn = log(n);
//	                     if (logn > myInfo.finger.size()){
//	                     if (logn > myInfo.finger.size()+1)
//	                     ERROR("finger size inceremented by more than one unit");
//	                     ////////////////////
//
//	                     }
//				 */
//
//	}else{ //DHT Node deleted
//		pred_suc_info* pred_suc = (pred_suc_info*)payload;
//		if (init_ip == sm->getInterfaceIP(GATEWAY_IFACE)){
//			WARNING("delete update packet circled succefully");
//			//xTODO
//		}
//		//check if pred
//		if (inRange(key, pred.key, me.key, E, E))
//			pred.update(pred_suc->pred_ip,pred_suc->pred_port);
//		//check if suc
//		if (inRange(key, me.key, suc.key, E, E))
//			succ.update(pred_suc->suc_ip,pred_suc->suc_port);
//
//		//update finger list
//		for (int i=0;i<(int)finger.size();i++)
//			if (inRange(key, (i==0 ? ))) //////////////////
//
//				//if finger list should get bigger
//				int logn = log(n);
//		if (logn < me.finger.size()){
//			if (logn < me.finger.size()-1)
//				ERROR("finger size decremented by more than one unit");
//			////////////////////
//		}
//
//	}
//}



