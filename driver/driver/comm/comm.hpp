#pragma once 
 #include "../basic.hpp" 
  
 class comm { 
 public: 
         static void run(); 
 private: 
         static void update_data(); 
         static std::uint64_t find_comm_ptr(const std::uint64_t& base); 
 private: 
 #pragma region SHARED_DATA 
         enum class request_e : std::uint8_t { 
                 NONE = 0, 
                 GET_PID, 
                 GET_MODULEBASE, 
                 READ_MEM, 
                 WRITE_MEM, 
                 DISCONNECT 
         }; 
         struct magic_sig_t { 
                 const std::uint64_t key = 0x44488567FFEui64; 
                 const std::uint64_t key2 = 0xFFFFFF33735ui64; 
  
                 inline const bool operator==(const magic_sig_t& o) { 
                         return key == o.key && key2 == o.key2; 
                 } 
         }; 
         struct shared_data_t { 
                 bool usermode_done = false; 
                 bool kernelmode_done = false; 
                 request_e request_type{}; 
                 void* pid{}; 
                 void* address{}; 
                 void* buffer{}; 
                 std::size_t size{}; 
                 const wchar_t* p_wstr{}; 
         }; 
 #pragma endregion SHARED_DATA 
 private: 
         inline static constexpr std::uint64_t confirm = 0x1888; 
         inline static const magic_sig_t magic_signature; 
         inline static PEPROCESS comm_process = nullptr; 
         inline static shared_data_t* shared_data = nullptr; 
         inline static std::uint64_t p_comm_address = 0; 
 };