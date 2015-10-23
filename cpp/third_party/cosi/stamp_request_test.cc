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
  std::cout << "hello\n";
  string test;
  test = Cosi::requestSignature("localhost", 2021, "test" );
  return -1;
}
