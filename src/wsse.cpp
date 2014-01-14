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

string Wsse::generate_timestamp(void) {
  time_t now;
  // ISO-8601 timestamps are 20 chars in length.
  char buf[21];

  // Current time.
  time(&now);

  // Get timestamp in ISO-8601 format.
  strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&now));

  this->timestamp = string(buf);
  return this->timestamp;
};

string Wsse::get_header(bool reset, const string profile) {
  string header;

  // Generate bits if required.
  this->generate_parts(reset);

  // Build header string in the format WSSE expects.
  header = profile +
    " Username=\"" + this->user + "\"," +
    " PasswordDigest=\"" + this->digest + "\"," +
    " Created=\"" + this->timestamp + "\"," +
    " Nonce=\"" + this->nonce_encoded + "\"";

  return header;
};

void Wsse::generate_parts(bool reset) {
  // Generate all required bits (re-generate if we're told to).
  if (this->nonce.empty() || reset) {
    this->generate_nonce();
  }
  if (this->timestamp.empty() || reset) {
    this->generate_timestamp();
  }
  if (this->nonce_encoded.empty() || reset) {
    this->nonce_encoded = this->b64_encode(this->nonce);
  }
  if (this->digest.empty() || reset) {
    this->digest = sha1_encode(this->nonce + this->timestamp + this->pass);
  }
};

/**
 * Inspired by http://stackoverflow.com/a/5331271/356237.
 */
string Wsse::b64_encode(const string& data) {
  BIO *bio;
  BIO *b64;
  int result;
  char* encoded_data;
  long length;
  string encoded;

  // Create a BIO to perform the encoding.
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);

  // Create a BIO that holds the encoded result.
  bio = BIO_new(BIO_s_mem()); // create BIO that holds the result

  // Chain 'bio' to 'b64' so that writing to b64 will put the base64-encoded
  // result in bio.
  BIO_push(b64, bio);

  // Attempt to encode the data.
  result = 0;
  while(true) {
    result = BIO_write(b64, data.data(), (int)data.size());

    // If we have a non-zero return, something went wrong, check if we should
    // retry.
    if (result <= 0) {
      if (BIO_should_retry(b64)) {
        continue;
      }
      else {
        // @TODO: custom exception.
        throw std::exception();
      }
    }
    else {
      break;
    }
  }

  // Flush the buffer.
  BIO_flush(b64);

  // Get a pointer to the encoded data.
  length = BIO_get_mem_data(bio, &encoded_data);

  // assign data to output
  encoded = string(encoded_data, length);

  return encoded;
};

string Wsse::sha1_encode(const string& data) {
  string encoded;
  unsigned char digest[SHA_DIGEST_LENGTH];
  char md_string[SHA_DIGEST_LENGTH * 2 + 1];
  SHA_CTX ctx;

  // Set context for SHA generator.
  SHA1_Init(&ctx);
  // Pass in data to be encoded to context.
  SHA1_Update(&ctx, data.c_str(), data.size());
  // Encode.
  SHA1_Final(digest, &ctx);

  // Convert encoded hex string back into binary.
  for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
    sprintf(&md_string[i * 2], "%02x", (unsigned int)digest[i]);
  }

  // Cast to string.
  encoded = string(md_string);

  return encoded;
};
