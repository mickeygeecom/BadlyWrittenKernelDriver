#pragma once 
 #include "../basic.hpp" 
  
 class utils { 
 public: 
         static void* get_driver_base(const char* mod_name); 
         static void* find_pattern(char* base, char* pattern, char* mask); 
         static std::uint64_t rva(std::uint8_t* address, std::uint64_t size); 
         static std::uint32_t get_process_id_by_name(const wchar_t* process_name); 
         static void memcpy(std::uint64_t destination, std::uint64_t source, std::size_t size); 
         static bool is_valid(void* ptr); 
         static bool copy_virtual_memory(PEPROCESS source_process, void* source_address, PEPROCESS target_process, void* target_address, std::size_t size); 
 private: 
         static void* find_pattern(char* base, std::uint32_t length, char* pattern, char* mask); 
         static bool check_mask(char* base, char* pattern, char* mask); 
 };