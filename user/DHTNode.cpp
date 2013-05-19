
#include "DHTNode.h"

DHTNode::DHTNode(){
    inNetwork = false;
    dataUptodate = false;
    fingerConsistent = false;
    perceivedN = 0;
    
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    pthread_mutex_init(&inNetwork_lock, NULL);
    pthread_mutex_init(&dataUptodate_lock, NULL);
    pthread_mutex_init(&fingerConsistent_lock, NULL);
    
    pthread_cond_init(&inNetwork_cond, NULL);
    pthread_cond_init(&dataUptodate_cond, NULL);
    pthread_cond_init(&fingerConsistent_cond, NULL);
    
    pthread_mutex_init(&cout_lock, NULL);
    pthread_mutex_init(&send_lock, NULL);


    pthread_mutex_init(&findSuc_lock, NULL);
    pthread_cond_init(&findSuc_cond, NULL);

    pthread_mutex_init(&transfer_lock, NULL);
    pthread_cond_init(&transfer_cond, NULL);

    pthread_mutex_init(&ack_lock, NULL);
    pthread_cond_init(&ack_cond, NULL);

    pthread_mutex_init(&dns_lock, NULL);
    pthread_cond_init(&dns_cond, NULL);

}

DHTNode::~DHTNode(){
    
    //destroy pthreads
}

bool DHTNode::get_inNetwork(){
	return inNetwork;
}
