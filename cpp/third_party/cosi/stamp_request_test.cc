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
#include "util/testing.h"
#include "util/status_test_util.h"

class StampRequestTest : public ::testing::Test {
protected:
  StampRequestTest(){
  }

  void SetUp() {
  }
};

using namespace std;

TEST_F(StampRequestTest, SignSTH){
  string test;
  VLOG(2) << "Requesting signature\n";
  VLOG(2) << Cosi::requestSignature("localhost", 2011, " 0 1 0 0 150FFFFFF56 0 0 0 0 0 0 0 0FFFFFF42FFFF1C14FFFFFFFFFF6FFF2427FF41FF64FFFF4CFFFFFF1B7852FF55" );

  ct::SignedTreeHead sth;
  sth.set_timestamp(1000);
  VLOG(2) << "Asking STH to be signed\n";
  string sth_signed = Cosi::SignTreeHead( &sth );
  VLOG(2) << sth_signed;
  ASSERT_NE(sth_signed, "");
  VLOG(2) << "Signature received\n";
}

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
