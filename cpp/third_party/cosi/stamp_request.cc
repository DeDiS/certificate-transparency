#include <iostream>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <arpa/inet.h>
#include "third_party/cosi/stamp_request.h"
#include "proto/serializer.h"
#include "util/json_wrapper.h"


namespace Cosi{
  using namespace std;

  string json_request = "{\"ReqNo\":0,\"Type\":1,\"Srep\":null,\"Sreq\":{\"Val\":\"";
  string json_request_end = "\"}}";
  string json_close = "{\"ReqNo\":1,\"Type\":3}\n";

  int connectTo(const string host, int port);
  int writeString(int m_sock, string msg);
  char *readString(int m_sock);
  char *HexToBytes(const string& hex);
  char *BytesToHex(const string& bytes);
  string requestSignature(const string host, int port, const string msg);

  #define MAXRECV 1024
  #define HOST "127.0.0.1"
  #define PORT 2011
  #define HOST_P "78.46.227.60"
  #define PORT_P 2011

  string SignTreeHead(ct::SignedTreeHead* sth){
    cout << "Asking to sign tree head\n";
    string host = HOST;
    int port = PORT;
    return requestSignature(host, port, sth->sha256_root_hash());
  }

  // Requests a signature from the stamp-server at host:port - returns NULL if
  // not successful or the string with the JSON-representation of the signature
  std::string requestSignature(const std::string host, int port, const std::string msg2 ){
    int m_sock = connectTo(host, port);
    if ( m_sock < 0 ){
      return NULL;
    }

    cout << "Binary message " << BytesToHex((const unsigned char*)msg2.c_str(), msg2.length()) << "\n";
    string msg = util::ToBase64(msg2);
    //string msg = "test";
    cout << "Sending json with message2: " << msg << "\n";
    string request = json_request + msg + json_request_end;
    cout << "Request is: " << request << "\n";
    if ( writeString(m_sock, request) < 0 ){
      cout << "Sending error\n";
      return NULL;
    }

    cout << "Waiting for string\n";

    string signature = readString(m_sock);
    cout << "Got signature " << signature << "\n";

    cout << "Sending stop\n";
    if ( writeString(m_sock, json_close) < 0 ){
      return NULL;
    }

    cout << "Returning signature " << signature << "\n";
    return signature;
  }

  int connectTo(const string host, int port){
    sockaddr_in m_addr;
    int m_sock = socket ( AF_INET, SOCK_STREAM, 0 );

    if ( m_sock == -1 ){
      return -1;
    }

    // TIME_WAIT - argh
    int on = 1;
    if ( setsockopt ( m_sock, SOL_SOCKET, SO_REUSEADDR, ( const char* ) &on, sizeof ( on ) ) == -1 ){
      return -1;
    }

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons ( port );

    int status = inet_pton ( AF_INET, host.c_str(), &m_addr.sin_addr );
    //int status = inet_pton ( AF_INET, "localhost", &m_addr.sin_addr );

    if ( errno == EAFNOSUPPORT ) return -1;

    cout << "Going to connect to " << host << "\n";
    status = ::connect ( m_sock, ( sockaddr * ) &m_addr, sizeof ( m_addr ) );
    cout << "Connected\n";

    if ( status < 0 ){
      return -1;
    }
    return m_sock;
  }

  int writeString(int m_sock, string msg){
    int status = ::write ( m_sock, msg.c_str(), msg.length() );

    if ( status == -1 ){
      int err=errno;
      cout << strerror(err);
      return -1;
    }
    return status;
  }

  char *readString(int m_sock){
    char *buf = (char*)malloc( MAXRECV + 1 );
    memset ( buf, 0, MAXRECV + 1 );
    int status = ::recv ( m_sock, buf, MAXRECV, 0 );
    if ( status == -1 ){
      free(buf);
      return NULL;
    }
    return buf;
  }

  char *HexToBytes(const string& hex) {
    char *bytes = (char*) malloc(hex.size());

    for (unsigned int i = 0; i < hex.length(); i += 2) {
      string byteString = hex.substr(i, 2);
      char byte = (char) strtol(byteString.c_str(), NULL, 16);
      bytes[i / 2] = byte;
    }

    return bytes;
  }

  char *BytesToHex(const unsigned char *bytes, int len) {
    char *hex = (char*) malloc(len * 2) + 1;

    for (unsigned int i = 0; i < len; i++) {
      sprintf(&hex[i * 2], "%02x", bytes[i]);
    }
    hex[2 * len] = 0;
    return hex;
  }
}
