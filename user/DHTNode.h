#ifndef DHT_NODE_H
#define DHT_NDDE_H 

#include "DHTNodeInfo.h"
#include "common.h"

#include <vector>
#include <map>
using namespace std;

class DHTNode{
public:
    DHTNode();
    ~DHTNode();
    bool get_inNetwork();

	DHTNodeInfo me,successor,predecessor;
	vector<DHTNodeInfo> finger;
	vector<ip_port> initial_possible_peers;
	map<string, uint32> dnsChache;

	int perceivedN;
    
    bool inNetwork;
    bool dataUptodate;
    bool fingerConsistent;
    
    pthread_attr_t attr;
    
    vector<pthread_t> threads;
    
    pthread_mutex_t inNetwork_lock;
    pthread_mutex_t dataUptodate_lock;
    pthread_mutex_t fingerConsistent_lock;
    
    pthread_cond_t inNetwork_cond;
    pthread_cond_t dataUptodate_cond;
    pthread_cond_t fingerConsistent_cond;
    
    pthread_mutex_t findSuc_lock;
    pthread_cond_t findSuc_cond;
    pthread_mutex_t transfer_lock;
    pthread_cond_t transfer_cond;
    pthread_mutex_t ack_lock;
    pthread_cond_t ack_cond;
    pthread_mutex_t dns_lock;
    pthread_cond_t dns_cond;



    pthread_mutex_t send_lock;
    pthread_mutex_t cout_lock;
    

    pred_suc_info find_suc_ans;
    byte find_suc_key[DHT_KEY_SIZE];
    uint32 find_suc_N;

    bool dns_found;
    ip_t dns_ans;

};


#endif
