//
//  wsse.hpp
//  wsse-cpp
//
//  Copyright (c) 2014 Chinthaka Godawita <chin.godawita@me.com>.
//
//  Distributed under the BSD license (see LICENSE for more or copy at
//  http://opensource.org/licenses/MIT).

#ifndef __wsse_cpp__wsse__
#define __wsse_cpp__wsse__

#include <iostream>
#include <string>
#include <ctime>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace std;

class Wsse {
public:
  string user;
  string pass;

  void set_user(string user);
  void set_pass(string pass);
  string get_header(bool reset = false, const string profile = "UsernameToken");

  Wsse(void);
  Wsse(string user, string pass);
  ~Wsse(void);

private:
  string nonce;
  string nonce_encoded;
  string timestamp;
  string digest;

  string generate_nonce(void);
  string generate_timestamp(void);
  void generate_parts(bool reset = false);
  string b64_encode(const string& data);
  string sha1_encode(const string& data, bool binary = true);

};

#endif /* defined(__wsse_cpp__wsse__) */
