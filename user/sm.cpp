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
#include "PacketDumper.h"

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
	stream >> me.port;
	me.ip = getInterfaceIP(GATEWAY_IFACE);
	me.update(me.ip, me.port);
	string gatewayMacStr;
	stream >> gatewayMacStr;
	cout << "before parsing mac " << gatewayMacStr << endl;
	char* token = strtok((char*)gatewayMacStr.c_str(), ":");

	for(int i=0;i<ETHER_ADDR_LEN;i++){
		gatewayMAC[i] = strtoul(token, NULL, 16);
		token = strtok(NULL, ":");
	}

	int n;
	stream >> n;
	initial_possible_peers.resize(n);
	for (int i=0;i<n;i++){
		string ipstr;
		stream >> ipstr;
		inet_pton(AF_INET,ipstr.c_str(),&initial_possible_peers[i].ip);
		stream >> initial_possible_peers[i].port;
	}

	successor.update(0, 0);
	predecessor.update(0, 0);

	cout << "finished initializing folani" << endl;
}

SimulatedMachine* sm;
void* startParsing(void* arg){
	PacketParser parser(sm);
	Frame* frame = (Frame*)arg;
	bool res = parser.parseFrame(*frame);
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
	cout << "Frame received at iface " << ifaceIndex <<
		" with length " << frame.length << endl;
	if (ifaceIndex != GATEWAY_IFACE)
		ERROR("expected packet from gateway interface, discarding packet")
	
    byte copy[frame.length];
    memcpy(copy, frame.data, frame.length);
    
    pthread_t thread;
    Frame packet(frame.length, copy);
    int rc = pthread_create(&thread, &attr, startParsing, (void*)(&packet));
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
			if (inNetwork){
				WARNING("already joined");
				continue;
			}
			//find succesor and predecessor
			WARNING("trying to join network");
			bool end = 0;
			for (int i=0;i<(int)initial_possible_peers.size();i++){
				LO cout << "initial possible peer " << i << " with " << initial_possible_peers[i].ip.s_addr << " " << initial_possible_peers[i].port << endl; ULO

				LOCK(sm->findSuc_lock);
				bool ret = parser.findSuccessor(me.key, successor, 1);
				UNLOCK(sm->findSuc_lock);

				if (ret){
					predecessor.update(find_suc_ans.pred.ip.s_addr, find_suc_ans.pred.port);
					successor.update(find_suc_ans.suc.ip.s_addr, find_suc_ans.suc.port);
					end = 1;
					break;
				}

			}
			perceivedN++;
			if (end){
				//update finger table
				pthread_t updateFinger_thread;
				PacketParser::updateFingerHelperParameter param;
				param.pp = &parser;
				param.n = perceivedN;
				pthread_create(&updateFinger_thread, &attr, PacketParser::updateFingerHelper, (void*)(&param));
				pthread_join(updateFinger_thread, NULL);

				//fetch data from successor
				//if (perceivedN > 1){
				//	pthread_t fetchData_thread;
				//	pthread_create(&fetchData_thread, &attr, PacketParser::fetchDataHelper, NULL);
				//	pthread_join(fetchData_thread, NULL);
				//}

				//send update to predecessor
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
			if (!inNetwork){
				WARNING("already out");
				continue;
			}
			if (perceivedN < 2){
				//clearCache();
			}else{
				//push data to successor
				//TODO
				//clearCache();

				//send update to predecessor
				perceivedN--;
				LOCK(sm->inNetwork_lock);
				parser.sendDHTUpdate(0,1);
				pthread_cond_wait(&sm->inNetwork_cond, &sm->inNetwork_lock);
				UNLOCK(sm->inNetwork_lock);
			}
			perceivedN = 0;
			finger.resize(0);
			successor.update(0, 0);
			predecessor.update(0, 0);

			WARNING("node left DHT network");
		}else if (command == "set"){
		
		}else if (command == "get"){
		
		}else if (command == "print"){
			char succ_ip_str[INET_ADDRSTRLEN];
			char pred_ip_str[INET_ADDRSTRLEN];
			uint32 suc = htonl(successor.ip);
			uint32 pred = htonl(predecessor.ip);
			inet_ntop(AF_INET, &suc ,succ_ip_str,sizeof(succ_ip_str));
			inet_ntop(AF_INET, &pred ,pred_ip_str,sizeof(pred_ip_str));
			LO
			cout << cyan(">Predecessor IP:\t") << pred_ip_str << endl;
			cout << cyan(">Successor IP:\t\t") << succ_ip_str << endl;
			cout << cyan(">DNS table:") << endl;
			//TODO
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
    


