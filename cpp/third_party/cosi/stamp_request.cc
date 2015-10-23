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


namespace Cosi{
  using namespace std;

  string json_request = "{\"ReqNo\":0,\"Type\":1,\"Srep\":null,\"Sreq\":{\"Val\":\"";
  string json_request_end = "\"}}";
  string json_close = "{\"ReqNo\":1,\"Type\":3}\n";

  int connectTo(const string host, int port);
  int writeString(int m_sock, string msg);
  char *readString(int m_sock);
  char *HexToBytes(const string& hex);
  string requestSignature(const string host, int port, const string msg);

  #define MAXRECV 1024

  string SignTreeHead(ct::SignedTreeHead* sth){
    cout << "Asking to sign tree head\n";
    string serialized_sth;
    Serializer::SerializeResult res =
    Serializer::SerializeSTHSignatureInput(*sth, &serialized_sth);
    if (res != Serializer::OK) return "error";

    return requestSignature("localhost", 2021, serialized_sth);
  }

  // Requests a signature from the stamp-server at host:port - returns NULL if
  // not successful or the string with the JSON-representation of the signature
  string requestSignature(const string host, int port, const string msg ){
    int m_sock = connectTo(host, port);
    if ( m_sock < 0 ){
      cout << "Connection error\n";
      return NULL;
    }

    string request = json_request + msg + json_request_end;
    cout << "Sending message: " + request + "\n";
    if ( writeString(m_sock, request) < 0 ){
      cout << "Error while writing signing request\n";
      return NULL;
    }

    string signature = readString(m_sock);;
    cout << "Got string: " << signature;

    cout << "Sending message: " + json_close;
    if ( writeString(m_sock, json_close) < 0 ){
      cout << "Error while asking to close\n";
      return NULL;
    }
    return signature;
  }

  int connectTo(const string host, int port){
    sockaddr_in m_addr;
    int m_sock = socket ( AF_INET, SOCK_STREAM, 0 );

    if ( m_sock == -1 ){
      cout << "could't create socket\n";
      return -1;
    }

    // TIME_WAIT - argh
    int on = 1;
    if ( setsockopt ( m_sock, SOL_SOCKET, SO_REUSEADDR, ( const char* ) &on, sizeof ( on ) ) == -1 ){
      cout << "could't connect\n";
      return -1;
    }

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons ( port );

    int status = inet_pton ( AF_INET, host.c_str(), &m_addr.sin_addr );

    if ( errno == EAFNOSUPPORT ) return -1;

    status = ::connect ( m_sock, ( sockaddr * ) &m_addr, sizeof ( m_addr ) );

    if ( status < 0 ){
      cout << "could't connect\n";
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
      cout << "status == -1   errno == " << errno << "  in Socket::recv\n";
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

    cout << hex.length() / 2;
    cout << " bytes converted\n";

    return bytes;
  }
}
