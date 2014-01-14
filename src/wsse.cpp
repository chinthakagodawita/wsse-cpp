//
//  wsse.cpp
//  wsse-cpp
//
//  Copyright (c) 2014 Chinthaka Godawita <chin.godawita@me.com>.
//
//  Distributed under the BSD license (see LICENSE for more or copy at
//  http://opensource.org/licenses/MIT).

#include "wsse.hpp"

Wsse::Wsse(string user, string pass) {
  // Seed rand() else it'll always be the same.
  srand(time(0));

  this->user = user;
  this->pass = pass;
};

Wsse::Wsse(void) : Wsse::Wsse("", "") {};

Wsse::~Wsse(void) {
};

void Wsse::set_user(string user) {
  this->user = user;
};

void Wsse::set_pass(string pass) {
  this->pass = pass;
};

string Wsse::generate_nonce(void) {
  string nonce;
  const char alpha_numeric[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  for (int i = 0; i < 16; ++i) {
    nonce += alpha_numeric[rand() % (sizeof(alpha_numeric) - 1)];
  }

  this->nonce = nonce;
  return this->nonce;
};
