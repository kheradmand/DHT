//                   In the name of GOD
/**
 * Partov is a simulation engine, supporting emulation as well,
 * making it possible to create virtual networks.
 *  
 * Copyright © 2009-2012 Behnam Momeni.
 * 
 * This file is part of the Partov.
 * 
 * Partov is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Partov is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Partov.  If not, see <http://www.gnu.org/licenses/>.
 *  
 */

#include "sm.h"

#include "interface.h"
#include "frame.h"
#include "OstreamManip.h"
#include "common.h"
#include "PacketParser.h"


#include <netinet/in.h>
#include <sys/time.h>
#include <sstream>

using namespace std;

SimulatedMachine::SimulatedMachine (const ClientFramework *cf, int count) :
	Machine (cf, count) {
	// The machine instantiated.
	// Interfaces are not valid at this point.
}

SimulatedMachine::~SimulatedMachine () {
	// destructor...
}

void SimulatedMachine::initialize () {

	cout << "initializing folani" << endl;
	sm = this;
	//PacketDumper::sm = this;
	string custom = getCustomInformation();
	stringstream stream(custom);
	uint16 port;
	stream >> port;
	uint32 ip = getInterfaceIP(GATEWAY_IFACE);
	me.update(ip, port);
	me.update(me.ip, me.port);
	//cout << "fuck you initialzer " << endl;
	//me.print();
	LO cout << "ahmag " << me.ip << " boz " << getInterfaceIP(GATEWAY_IFACE) << endl; ULO;
	string gatewayMacStr;
	stream >> gatewayMacStr;
	cout << "before parsing mac " << gatewayMacStr << endl;
	char* token = strtok((char*)gatewayMacStr.c_str(), ":");

	for(int i=0;i<ETHER_ADDR_LEN;i++){
		LO cout << "TOKEN " <<  strtoul(token, NULL, 16) << endl; ULO
		gatewayMAC[i] = strtoul(token, NULL, 16);
		token = strtok(NULL, ":");
	}
	for (int i=0;i<ETHER_ADDR_LEN;i++){
		LO cout << HEXOUT(gatewayMAC[i]) << " "; ULO
	}
	LO cout << endl; ULO
	int n;
	stream >> n;
	initial_possible_peers.resize(n);
	for (int i=0;i<n;i++){
		string ipstr;
		stream >> ipstr;
		uint32 nip;
		inet_pton(AF_INET,ipstr.c_str(),&nip);
		initial_possible_peers[i].ip.s_addr = ntohl(nip);
		stream >> initial_possible_peers[i].port;
	}

	successor.update(0, 0);
	predecessor.update(0, 0);

	cout << "finished initializing folani" << endl;
}


void* startParsing(void* arg){
	SimulatedMachine::startParsingArgument* info = (SimulatedMachine::startParsingArgument*)arg;
	PacketParser parser(info->sm);
	Frame *frame = info->frame;
	bool res = parser.parseFrame(*frame);
	//delete info->frame->data;
	pthread_exit((void*)res);
}

/**
 * This method is called from the main thread.
 * Also ownership of the data of the frame is not with you.
 * If you need it, make a copy for yourself.
 *
 * You can also send frames using:
 * <code>
 *     bool synchronized sendFrame (Frame frame, int ifaceIndex) const;
 * </code>
 * which accepts one frame and the interface index (counting from 0) and
 * sends the frame on that interface.
 * The Frame class used here, encapsulates any kind of network frame.
 * <code>
 *     class Frame {
 *     public:
 *       uint32 length;
 *       byte *data;
 *
 *       Frame (uint32 _length, byte *_data);
 *       virtual ~Frame ();
 *     };
 * </code>
 */
void SimulatedMachine::processFrame (Frame frame, int ifaceIndex) {

	sm = this;
	LO cout << "Frame received at iface " << ifaceIndex <<
		" with length " << frame.length << endl; ULO
	if (ifaceIndex != GATEWAY_IFACE)
		ERROR("expected packet from gateway interface, discarding packet")
	
    byte* copy = new byte[frame.length];
    memcpy(copy, frame.data, frame.length);
    Frame* packet = new Frame(frame.length, copy);
    startParsingArgument* arg = new startParsingArgument;
    pthread_t* thread = new pthread_t;

    arg->sm = this;
    arg->frame = packet;
    int rc = pthread_create(thread, &attr, startParsing, (void*)(arg));
    if (rc)
    	ERROR("failed creating new thread")


}




/**
 * This method will be run from an independent thread. Use it if needed or simply return.
 * Returning from this method will not finish the execution of the program.
 */
void SimulatedMachine::run () {
	while (true){
		PacketParser parser(this);
		cout << "Enter commnad: ";
		string commandstr;
		getline(cin,commandstr);
		stringstream commandstream(commandstr);
		string command;
		commandstream >> command;
		if (command == "join"){

			if (get_inNetwork()){
				WARNING("already joined");
				continue;
			}
			//find succesor and predecessor
			WARNING("trying to join network");
			bool end = 0;
			for (int i=0;i<(int)initial_possible_peers.size();i++){
				LO cout << "initial possible peer " << i << " with " << initial_possible_peers[i].ip.s_addr << " " << initial_possible_peers[i].port << endl; ULO

				DHTNodeInfo whotoask(initial_possible_peers[i].ip.s_addr, initial_possible_peers[i].port);

				bool ret = parser.findSuccessor(me.key, whotoask, 1);
				UNLOCK(sm->findSuc_lock);
				LO cout << "ret from find succesoor is " << ret << endl; ULO
				if (ret){
					WARNING("here");
					predecessor.update(find_suc_ans.pred.ip.s_addr, find_suc_ans.pred.port);
					successor.update(find_suc_ans.suc.ip.s_addr, find_suc_ans.suc.port);
					end = 1;
					WARNING("there");
					break;
				}

			}
			ERROR("found successor (mayble myself)")
			perceivedN++;
			LO cout << "pervN after finding suc is " << perceivedN << endl; ULO
			if (end){
				//update finger table
				WARNING("updating finger table")
				pthread_t updateFinger_thread;
				PacketParser::updateFingerHelperParameter param;
				param.pp = &parser;
				param.n = perceivedN;
				//pthread_create(&updateFinger_thread, &attr, PacketParser::updateFingerHelper, (void*)(&param));
				//pthread_join(updateFinger_thread, NULL);
				//PacketParser::updateFingerHelper((void*)(&param));
				parser.updateFinger(perceivedN);

				//fetch data from successor
				LOCK(transfer_lock);
				parser.sendDHTTransferQuery();
				pthread_cond_wait(&transfer_cond, &transfer_lock);
				UNLOCK(transfer_lock);

				LOCK(sm->inNetwork_lock)
				inNetwork = 1;
				UNLOCK(sm->inNetwork_lock)

				//send update to predecessor
				WARNING("sending update to pred")
				LOCK(sm->inNetwork_lock);
				parser.sendDHTUpdate(1,1);
				pthread_cond_wait(&sm->inNetwork_cond, &sm->inNetwork_lock);
				UNLOCK(sm->inNetwork_lock);

			}else{ //i am the only one
				//ERROR("i am the only one!");
				LO cout << " i am the only one " << endl; ULO
				successor.update(me.ip, me.port);
				predecessor.update(me.ip, me.port);
				LOCK(inNetwork_lock)
				inNetwork = 1;
				UNLOCK(inNetwork_lock);
				finger.resize(1);
				finger[0].update(me.ip, me.port);
			}
			WARNING("node joined DHT network");
		}else if (command == "leave"){
			if (!get_inNetwork()){
				WARNING("already out");
				continue;
			}
			if (perceivedN >=2){
				//push data to successor
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
				parser.sendDHTTransfer(1);
				//pthread_cond_wait(&sm->ack_cond, &sm->ack_lock);
				//UNLOCK(sm->ack_lock);

				//send update to predecessor
				perceivedN--;
				LOCK(sm->inNetwork_lock);
				parser.sendDHTUpdate(0,1);
				pthread_cond_wait(&sm->inNetwork_cond, &sm->inNetwork_lock);
				UNLOCK(sm->inNetwork_lock);
			}else{
				LOCK(sm->inNetwork_lock);
				inNetwork = 0;
				UNLOCK(sm->inNetwork_lock);
			}

			perceivedN = 0;
			finger.resize(0);
			successor.update(0, 0);
			predecessor.update(0, 0);
			dnsChache.clear();

			WARNING("node left DHT network");
		}else if (command == "set"){
			if (!get_inNetwork()){
				WARNING("node not in network");
				continue;
			}
			string k;
			commandstream >> k;
			ip_t v;
			commandstream >> v;
			parser.sendDHTDNSSet(k, v);
		}else if (command == "get"){
			if (!get_inNetwork()){
				WARNING("node not in network");
				continue;
			}
			string k;
			commandstream >> k;
			parser.DNSQuery(k);
			if (!dns_found){
				ERROR("\t>not found!")
			}else{
				LO cout << green("\t->\t"+k) << "\t" << dns_ans << endl; ULO
			}
		}else if (command == "print"){
			char succ_ip_str[INET_ADDRSTRLEN];
			char pred_ip_str[INET_ADDRSTRLEN];
			char mme_ip_str[INET_ADDRSTRLEN];
			char finger_ip_str[INET_ADDRSTRLEN];
			uint32 suc = htonl(successor.ip);
			uint32 pred = htonl(predecessor.ip);
			uint32 mme = htonl(me.ip);
			inet_ntop(AF_INET, &suc ,succ_ip_str,sizeof(succ_ip_str));
			inet_ntop(AF_INET, &pred ,pred_ip_str,sizeof(pred_ip_str));
			inet_ntop(AF_INET, &mme ,mme_ip_str,sizeof(mme_ip_str));
			LO
			cout /*<< cyan(">Mymymymym IP:\t\t")*/ << mme_ip_str << endl;
			cout << cyan(">Predecessor IP:\t") << pred_ip_str << endl;
			cout << cyan(">Successor IP:\t\t") << succ_ip_str << endl;
			cout << cyan(">Nodes in net:\t\t") << perceivedN << endl;
			cout << cyan(">Finger table:\t\t") << endl;
			for (int i=0;i<(int)finger.size();i++){
				uint32 fing = htonl(finger[i].ip);
				inet_ntop(AF_INET, &fing, finger_ip_str,sizeof(finger_ip_str));
				cout << "\t" << i << ":\t" << finger_ip_str << "\t" << finger[i].port << endl;
			}
			cout << cyan(">DNS table:") << endl;
			for (typeof(dnsChache.begin()) i=dnsChache.begin();i!=dnsChache.end();i++)
				cout << "\t" << i->first << "\t\t" << i->second << endl;
			ULO
		}else{
			cout << red("unsupported command") << endl;	
		}
	}
}


/**
 * You could ignore this method if you are not interested on custom arguments.
 */
void SimulatedMachine::parseArguments (int argc, char *argv[]) {
	// TODO: parse arguments which are passed via --args
}




byte* SimulatedMachine::getInterfaceMAC (int interface) {
	if (interface<0 || interface >= countOfInterfaces)
		EXIT("interface index out of bound",1);
	return iface[interface].mac;
}
ip_t SimulatedMachine::getInterfaceIP (int interface) {
	if (interface<0 || interface >= countOfInterfaces)
		EXIT("interface index out of bound",1);
	return iface[interface].getIp();
}

byte* SimulatedMachine::getGatewayMAC(){
	return gatewayMAC;
}



//bool SimulatedMachine::send(Frame frame, int interface) {
//	//PacketDumper::dumpPacket(frame, interface, 1);
//	if (sendFrame(frame, interface)){
//		cout << green("packet sent successfully") << endl;
//		return 1;
//	}else{
//		cout << red("packet send failed") << endl;
//		return 0;
//	}
//}
    


