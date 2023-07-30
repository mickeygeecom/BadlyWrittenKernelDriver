#pragma once 
 #include "../basic.hpp" 
  
 class meme { 
 public: 
         static NTSTATUS setup(const std::uint64_t mdl); 
 private: 
         static void thread(); 
         static bool null_pfn(PMDL mdl); 
 };