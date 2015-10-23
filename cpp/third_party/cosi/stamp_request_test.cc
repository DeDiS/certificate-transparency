#include <iostream>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "stamp_request.h"

using namespace std;

int main(){
  string test;
  cout << "Requesting signature\n";
  cout << Cosi::requestSignature("78.46.227.60", 2001, "test" );

  ct::SignedTreeHead sth;
  sth.set_timestamp(1000);
  cout << "Asking STH to be signed\n";
  cout << Cosi::SignTreeHead( &sth );
  cout << "Signature received\n";
  return 0;
}
