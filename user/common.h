#ifndef COMMON_H
#define COMMON_H

#include "partovdef.h"
#include "OstreamManip.h"

#include <iomanip>
#include <cstdlib>
#include <arpa/inet.h>
using namespace std;

#define LOCK(td) {pthread_mutex_lock(&(td));}
#define UNLOCK(td) {pthread_mutex_unlock(&(td));}
#define LO {LOCK(sm->cout_lock)}
#define ULO {UNLOCK(sm->cout_lock)}
#define WARNING(str) {LO cout << yellow(str) << endl; ULO}
#define ERROR(str) {LOCK(sm->cout_lock) cout << red(str) << endl; UNLOCK(sm->cout_lock)}
#define RETURN(str,ec) {LOCK(sm->cout_lock) cout << pthread_self() << red(str) << endl; UNLOCK(sm->cout_lock) return (ec); }
#define EXIT(str,ec) {LOCK(sm->cout_lock) cout << bold(red(str)) << endl; UNLOCK(sm->cout_lock) exit(ec);}
#define HEXOUT(num) setfill('0') << setw(2) << hex << (int)num << dec
#define UWARNING(str) { cout << yellow(str) << endl; }
#define UERROR(str) { cout << red(str) << endl; }
#define URETURN(str,ec) { cout << pthread_self() << red(str) << endl;  return (ec); }
#define UEXIT(str,ec) {cout << bold(red(str)) << endl;  exit(ec);}


#define GATEWAY_IFACE 0
#define DHT_KEY_SIZE 20
#define MAX_LOG_NODES 160

#define WAIT_TIME 2

#define E 0 //exclusive
#define I 1 //inlcusive


typedef uint32 ip_t;
typedef uint64 mac_t;
typedef uint16 port_t;

struct ip_port{
    struct in_addr ip;
    port_t port;
};

struct pred_suc_info{
    ip_port suc;
    ip_port pred;
};


#endif
