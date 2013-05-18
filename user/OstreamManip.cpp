#include "common.h"
#include <string>
using namespace std;

string bold(const string& s){
	return "\033[01m"+s+"\033[0m";
}
string green(const string& s){
	return "\033[32m"+s+"\033[0m";
}
string red(const string& s){
	return "\033[31m"+s+"\033[0m";
}
string yellow(const string& s){
	return "\033[33m"+s+"\033[0m";
}
string magenta(const string& s){
	return "\033[35m"+s+"\033[0m";
}
string cyan(const string& s){
	return "\033[36m"+s+"\033[0m";
}
string greenbg(const string& s){
	return "\033[42m"+s+"\033[0m";
}
string redbg(const string& s){
	return "\033[41m"+s+"\033[0m";
}
string yellowbg(const string& s){
	return "\033[43m"+s+"\033[0m";
}
string blink(const string& s){
	return "\033[5m"+s+"\033[0m";
}
string int2bin(int n){
	string ret="";
	for (int i=0;i<32;i++){
		ret=(n%2? "1" : "0")+ret;
		n>>=1;
	}
	return ret;
}


