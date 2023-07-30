#pragma once 
 #include <cstdint> 
 #include <ntifs.h> 
 #include <ntimage.h> 
 #include "meme/undoc.hpp" 
 #include "skCrypter.hpp" 
  
// #define DEBUG 
 #ifdef DEBUG 
 #define printf(...) DbgPrintEx(0, 0, __VA_ARGS__) 
 #else 
 #define printf(...) 
 #endif 
  
 namespace std { using ::size_t; }