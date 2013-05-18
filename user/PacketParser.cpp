#include "PacketParser.h"
#include "common.h"
#include "sr_protocol.h"
#include "sm.h"

#include <iostream>
#include <cmath>
#include <sys/time.h>
using namespace std;

PacketParser::PacketParser(SimulatedMachine* _sm){
	sm = _sm;
}



bool PacketParser::parseFrame(Frame frame){
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
	//int hlen = sizeof(ip);
	ip* ip_header = (ip*)frame.data;
	if (!verifyChecksum(ip_header))
		RETURN("checksum not verified, discarding packet",0)
	ip_src = ntohl(ip_header->ip_src.s_addr);
	ip_dst = ntohl(ip_header->ip_dst.s_addr);

	if (ip_dst != sm->getInterfaceIP(GATEWAY_IFACE))
		RETURN("packet is not for me, discarding packet",0)

	if (ip_header->ip_p != IPPROTO_UDP)
		RETURN("expected UDP protocol, discarding packet",0)

    return parseUDP(Frame(frame.length-sizeof(ip),frame.data+sizeof(ip)));
}

bool PacketParser::parseUDP(Frame frame){


    sr_udp* udp_header = (sr_udp*)(frame.data);
    port_src = ntohs(udp_header->port_src);
    port_dst = ntohs(udp_header->port_dst);
    if (port_src != sm->me.port)
        RETURN("unexpected port number, discarding packet",0)

    return parseDHT(Frame(frame.length-sizeof(sr_udp), frame.data+sizeof(sr_udp)));

}

bool PacketParser::parseDHT(Frame frame){
    
    
    dht_hdr* dht_header = (dht_hdr*)(frame.data);
    init_ip = ntohl(dht_header->init_ip.s_addr);
    init_port = ntohs(dht_header->init_port);
    key = dht_header->key;
    control = ntohs(dht_header->control);
    flags = control >> 8;
    operation = (byte)(control & DHT_OPER_MASK);
    N = ntohl(dht_header->n);
    sm->perceivedN = N;
    
    Frame payload(frame.length-sizeof(dht_hdr), frame.data+sizeof(dht_hdr));
    
    
    
    switch (operation) {
        case DHT_OPER_FIND_SUCC:
        	return parseDHTFindSuccessor(payload);
            break;
        case DHT_OPER_UPDATE:
            return parseDHTUpdate(payload);
            break;
        case DHT_OPER_GET:
            return parseDHTGet(payload);
            break;
        case DHT_OPER_SET:
            return parseDHTSet(payload);
            break;
        default:
            RETURN("unexpected DHT operation",0);
            break;
    }

    return 0;
}

bool PacketParser::parseDHTFindSuccessor(Frame frame){

	if (flags & DHT_QUERY){ //FIND_SUCC Query
		if (!sm->get_inNetwork())
			RETURN("Node is not in DHT network but received FIND_SUCCESSOR Query, discarding",0);
		if (inRange(key, sm->predecessor.key, sm->me.key, E, I)){
			//I am the successor! pred=my pre suc=me
			pred_suc_info response;
			response.pred.ip.s_addr = sm->predecessor.ip;
			response.pred.port = sm->predecessor.port;
			response.suc.ip.s_addr = sm->me.ip;
			response.suc.port = sm->me.port;
			return sendDHTFindSuccessorResponse(response);
		}else{
			for (int i=sm->finger.size()-1;i>=0;i--)
				if (inRange(sm->finger[i].key, sm->me.key, key, E, E)){
					return sendDHTFindSuccessorQuery(sm->finger[i]);
				}
			WARNING("found no finger, forwarding");
			return sendDHTFindSuccessorQuery(sm->successor);
		}

	}else{  //FIND_SUCC Ans
		if (init_ip != sm->me.ip)
			RETURN("received find successor response, but its not for me!",0);
		//signal mikonim, thread ha mibinan age key e morede nazareshoon bood bar midaran
		LOCK(sm->findSuc_lock);
		pred_suc_info* ans = (pred_suc_info*)frame.data;
		ntoh_pred_suc_info(&(sm->find_suc_ans),ans);
		pthread_cond_broadcast(&sm->findSuc_cond);
		UNLOCK(sm->findSuc_lock);
		return 1;
	}
	return 0;

}

bool PacketParser::parseDHTUpdate(Frame frame){
	if (flags & DHT_ADDED){
		if (init_ip == sm->getInterfaceIP(GATEWAY_IFACE)){
			WARNING("add update packet circled successfully");
			//ehtemalan hame kara ghablan shode :-?
			//finger haye khodesho peida kone
			//elaat ro az suc begire
			//in network hesab she
			LOCK(sm->inNetwork_lock);
			sm->inNetwork = 1;
			pthread_cond_signal(&sm->inNetwork_cond);
			UNLOCK(sm->inNetwork_lock);
			return 1;
		}else{
			//check if pred
			if (inRange(key, sm->predecessor.key, sm->me.key, E, E))
				sm->predecessor.update(init_ip,init_port);
			//check if suc
			if (inRange(key, sm->me.key, sm->successor.key, E, E))
				sm->successor.update(init_ip,init_port);

			updateFingerHelperParameter param;
			param.pp = this;
			param.n = N;
			int rc = pthread_create(&updateFinger_thread, &sm->attr, updateFingerHelper, (void*)(&param));
			if (rc)
				RETURN("failed creating new thread",0);

			return sendDHTUpdate(1);
		}
	}else{ //deleted
		if (init_ip == sm->getInterfaceIP(GATEWAY_IFACE)){
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

			//check if pred
			if (inRange(key, sm->predecessor.key, sm->me.key, E, E))
				sm->predecessor.update(pred_suc.pred.ip.s_addr, pred_suc.pred.port);
			//check if suc
			if (inRange(key, sm->me.key, sm->successor.key, E, E))
				sm->successor.update(pred_suc.suc.ip.s_addr, pred_suc.suc.port);
			updateFingerHelperParameter param;
			param.pp = this;
			param.n = N;
			int rc = pthread_create(&updateFinger_thread, &sm->attr, updateFingerHelper, (void*)(&param));
			if (rc)
				RETURN("failed creating new thread",0)

			return sendDHTUpdate(1);
		}
	}
	return 0;
}

bool PacketParser::parseDHTGet(Frame frame){
/*
	if (flags & DHT_QUERY){

	}else {
		if (flags & DHT_FOUND)
	}
*/
	return 0;
}


bool PacketParser::parseDHTSet(Frame frame){
	return 0;
}

void PacketParser::fillDefaultDHTHeader(dht_hdr* header){
	header->init_ip.s_addr = htonl(init_ip);
	header->init_port = htons(init_port);
	memcpy(header->key, key, DHT_KEY_SIZE);
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

	fillDefaultDHTHeader(dht_header);
	dht_header->control = htons(DHT_OPER_FIND_SUCC | DHT_QUERY);

	if (init){
		dht_header->init_ip.s_addr = htonl(sm->me.ip);
		dht_header->init_port = htons(sm->me.port);
		memcpy(dht_header->key, thekey, DHT_KEY_SIZE);
	}

	return sendDHTPacket(frame, target.ip, target.port);
}

bool PacketParser::sendDHTUpdate(bool added, bool init){
	byte payload[sizeof(dht_hdr)+(added? 0 : sizeof(pred_suc_info))];
	Frame frame(sizeof(payload),payload);

	dht_hdr* dht_header = (dht_hdr*)payload;
	pred_suc_info* next;
	if (!added){
		next = (pred_suc_info*)(payload+sizeof(dht_hdr));
		pred_suc_info info;
		info.pred.ip.s_addr = sm->predecessor.ip;
		info.suc.ip.s_addr = sm->successor.ip;
		info.pred.port = sm->predecessor.port;
		info.suc.port = sm->successor.port;
		hton_pred_suc_info(next, &info);
	}

	fillDefaultDHTHeader(dht_header);
	dht_header->control = htons(DHT_OPER_UPDATE | (added? DHT_ADDED : 0));

	if (init){
		dht_header->init_ip.s_addr = htonl(sm->me.ip);
		dht_header->init_port = htons(sm->me.port);
		memcpy(dht_header->key, sm->me.key, DHT_KEY_SIZE);
	}

	return sendDHTPacket(frame, sm->predecessor.ip, sm->predecessor.port);
}

bool PacketParser::sendDHTPacket(Frame frame, ip_t target_ip, port_t target_port){
	byte payload[sizeof(sr_ethernet_hdr)+sizeof(ip)+sizeof(sr_udp)+frame.length];
	Frame packet(sizeof(payload),payload);

	sr_ethernet_hdr* ether_header = (sr_ethernet_hdr*)payload;
	ip* ip_header = (ip*)(payload+sizeof(sr_ethernet_hdr));
	sr_udp* udp_header = (sr_udp*)(payload+sizeof(sr_ethernet_hdr)+sizeof(ip));
	dht_hdr* dht_header = (dht_hdr*)(payload+sizeof(sr_ethernet_hdr)+sizeof(ip)+sizeof(sr_udp));

	memcpy(ether_header->ether_shost, sm->getInterfaceMAC(GATEWAY_IFACE), sizeof(ETHER_ADDR_LEN));
	memcpy(ether_header->ether_dhost, sm->getGatewayMAC(), sizeof(ETHER_ADDR_LEN));
	ether_header->ether_type = htons(ETHERTYPE_IP);

	memset(ip_header, 0, sizeof(ip));
	ip_header->ip_v = 4;
	ip_header->ip_hl = 5;
	ip_header->ip_len = htons(frame.length);
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
	bool ret = sendFrame(frame);
	UNLOCK(sm->send_lock);
	if (!ret)
		RETURN("failed sending packet",0);

	return ret;
}

bool PacketParser::sendFrame(Frame frame){
	int c = 100;
	while (c-- && !sm->sendFrame(frame, GATEWAY_IFACE));
	return (c>=0);
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
	int comp = (memcmp(key, from, DHT_KEY_SIZE));
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

void* PacketParser::updateFingerHelper(void* arg){
	updateFingerHelperParameter* param = (updateFingerHelperParameter*)arg;
	param->pp->updateFinger(param->n);
	return NULL;
}

static void* fetchDataHelper(void* arg){

}

void PacketParser::updateFinger(uint32 n){
	if (n == 0){
		pthread_exit(NULL);
	}
	int m = log2((double)n);
	int lastSize = sm->finger.size();
	sm->finger.resize(m+1,DHTNodeInfo(0,0));
	sm->finger[0].update(sm->successor.ip, sm->successor.port);

	if (n==1){
		for (int i=0;i<(int)sm->finger.size();i++)
			sm->finger[i].update(sm->me.ip, sm->me.port);
		pthread_exit(NULL);
	}

	int mn = min(m, lastSize);
	for (int i=1;i<mn-1;i++){
		if (inRange(getFingerStart(i+1), sm->me.key, sm->finger[i].key, I, E)){
			sm->finger[i+1].update(sm->finger[i].ip, sm->finger[i].port);
		}else{

			bool ret = findSuccessor(getFingerStart(i+1), sm->successor);
			if (!ret)
				ERROR("finding successor in finger update failed")
			else
				sm->finger[i+1].update(sm->find_suc_ans.suc.ip.s_addr, sm->find_suc_ans.suc.port);
			UNLOCK(sm->findSuc_lock);


		}
	}
	for (int i=mn+1;i<(int)sm->finger.size();i++){
		bool ret = findSuccessor(getFingerStart(i), sm->successor);
		if (!ret)
			ERROR("finding successor in finger update failed")
		else
			sm->finger[i].update(sm->find_suc_ans.suc.ip.s_addr, sm->find_suc_ans.suc.port);
		UNLOCK(sm->findSuc_lock);
	}
	pthread_exit(NULL);
}

//in tabe vaghti barmigarde findSuc_lock lock hastesh
bool PacketParser::findSuccessor(byte* thekey, DHTNodeInfo whotoask, bool timed){
	LOCK(sm->findSuc_lock);
	bool b = sendDHTFindSuccessorQuery(whotoask, 1, thekey);
	LO cout << "sendDHTFindSuccessorQuery returned with " << b << endl; ULO
	DHTNodeInfo info(0,0);
	int rc;

	timeval now;
	gettimeofday(&now, NULL);
	timespec t;
	t.tv_sec = now.tv_sec + 3;
	t.tv_nsec = 0;

	do {
		if (timed){
			rc = pthread_cond_timedwait(&sm->findSuc_cond, &sm->findSuc_lock, &t);
			if (rc) break;
		}else
			rc = pthread_cond_wait(&sm->findSuc_cond, &sm->findSuc_lock);
		info.update(sm->find_suc_ans.suc.ip.s_addr,sm->find_suc_ans.suc.port);
	} while (memcmp(thekey, info.key, DHT_KEY_SIZE)!=0);
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
	//cout << yellow("sum") << HEXOUT(sum) << endl;
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



