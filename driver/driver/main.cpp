#include "basic.hpp" 
 #include "meme/meme.hpp" 
  
 extern "C" NTSTATUS driver_entry(std::uint64_t mdl, PUNICODE_STRING p_registry_path) { 
         UNREFERENCED_PARAMETER(p_registry_path); 
  
         return meme::setup(mdl); 
 }