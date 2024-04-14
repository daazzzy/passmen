#include <cryptopp/secblock.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;

std::string encrypt(const std::string& plain, const std::string& key){
  std::string encrypted;
  SecByteBlock keyb((const unsigned char*)key.data(), key.size());
  ECB_Mode<AES>::Encryption e;
  e.SetKey(keyb, keyb.size());

  StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(encrypted)));
  
  return encrypted;
}

std::string decrypt(const std::string& encrypted, const std::string& key){
  std::string decrypted;
  SecByteBlock keyBytes((const unsigned char*)key.data(), key.size());
  CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryptor;
  decryptor.SetKey(keyBytes, keyBytes.size());

  StringSource(encrypted, true, new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(decrypted)));
  return decrypted;
}


int main(int argc, char** argv){
  std::unordered_map<std::string, std::string> pass;
  std::string key = "u85EHBBZo+2hrGPd6ZNtmA=="; // 128bit key
  std::string plaintext = "Hello, World!";

  std::string encryptedText = encrypt(plaintext, key);
  std::cout << "Encrypted: " << encryptedText << std::endl;

  std::string decryptedText = decrypt(encryptedText, key);
  std::cout << "Decrypted: " << decryptedText << std::endl;

 

  return 0;
}
