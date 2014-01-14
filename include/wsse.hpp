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

using namespace std;

class Wsse {
public:
  string user;
  string pass;

  void set_user(string user);
  void set_pass(string pass);
  string get_auth();

  Wsse(void);
  Wsse(string user, string pass);
  ~Wsse(void);

private:
  string nonce;
  string timestamp;

  string generate_nonce(void);
  string generate_timestamp(void);

};

#endif /* defined(__wsse_cpp__wsse__) */
