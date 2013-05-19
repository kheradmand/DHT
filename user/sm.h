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

#ifndef _S_M_H_
#define _S_M_H_

#include "machine.h"
#include "DHTNode.h"
#include "sr_protocol.h"

class SimulatedMachine : public Machine, public DHTNode {
private:
	byte gatewayMAC[ETHER_ADDR_LEN];
public:
	SimulatedMachine* sm;

	SimulatedMachine (const ClientFramework *cf, int count);
	virtual ~SimulatedMachine ();

	virtual void initialize ();
	virtual void run ();
	virtual void processFrame (Frame frame, int ifaceIndex);
	friend void* startParsing(void* arg);
	
	struct startParsingArgument{
		SimulatedMachine* sm;
		Frame* frame;
	};
	static void parseArguments (int argc, char *argv[]);
    
	friend class PacketParser;
    
    byte* getInterfaceMAC(int interface);
	ip_t getInterfaceIP(int interface);
	byte* getGatewayMAC();
	//bool send(Frame frame, int interface);

    
};

#endif /* sm.h */

