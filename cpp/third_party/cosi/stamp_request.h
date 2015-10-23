#include "proto/ct.pb.h"

namespace Cosi{
  std::string requestSignature(const std::string host, int port, const std::string msg);
  std::string SignTreeHead(ct::SignedTreeHead* sth);
}
