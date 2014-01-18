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

  /**
   * Set the username for the authentication header.
   *
   * @param user Username to set.
   */
  void set_user(string user);

  /**
   * Set the password for the authentication header.
   *
   * @param pass Password to set.
   */
  void set_pass(string pass);

  /**
   * Generates and returns the value of the 'X-WSSE' authentication header.
   *
   * @param reset Whether or not to regenerate the nonce and timestamp values.
   * @param profile The token to provide as the 'profile' part of the header.
   *
   * @return The generated header value.
   */
  string get_header(bool reset = false, const string profile = "UsernameToken");

  Wsse(void);
  Wsse(string user, string pass);
  ~Wsse(void);

private:
  string nonce;
  string nonce_encoded;
  string timestamp;
  string digest;

  /**
   * Generates a nonce.
   *
   * @return The generated nonce.
   */
  string generate_nonce(void);

  /**
   * Gets the current time in ISO8601 timestamp format.
   *
   * @return The generated timestamp.
   */
  string generate_timestamp(void);

  /**
   * Generates all required parts for the header.
   *
   * @param reset Whether or not to regenerate cached values.
   */
  void generate_parts(bool reset = false);

  /**
   * Encodes a string into base 64.
   *
   * @param data The data to encode.
   *
   * @return The base64 encoded data.
   */
  string b64_encode(const string& data);

  /**
   * Encodes a string into a SHA1 hash.
   *
   * @param data The data to encode.
   * @param binary Whether or not to return the binary encoded hash or to
   * decode it prior to returning.
   *
   * @return The SHA1 hash.
   */
  string sha1_encode(const string& data, bool binary = true);

};

#endif /* defined(__wsse_cpp__wsse__) */
