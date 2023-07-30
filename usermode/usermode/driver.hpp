#pragma once 
#include <cstdint> 
#include <mutex> 

class driver {
public:
    static void initialize();
    static void set_pid(const std::uint32_t pid);
    static std::uint32_t get_pid(const wchar_t* process_name);
    static std::uint64_t get_modulebase(const wchar_t* module_name, const std::uint32_t pid = game_pid);
    static void read_memory(void* address, void* buffer, const std::size_t size);
    static void write_memory(void* address, void* buffer, const std::size_t size);
    template <typename type>
    inline static const type& read(const std::uint64_t address) {
        type buffer{};
        read_memory((void*)address, &buffer, sizeof(buffer));
        return buffer;
    }
    template <typename type>
    inline static void write(const std::uint64_t address, const type& value) {
        write_memory((void*)address, (void*)&value, sizeof(value));
    }
    static void disconnect();
private:
    static void send_request();
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
    struct comm_t {
        magic_sig_t magic_signature;
        shared_data_t** comm_ptr = nullptr;
    };
private:
    inline static constexpr std::uint64_t confirm = 0x1888;
    inline static comm_t comm;
    inline static shared_data_t* shared_data = nullptr;
    inline static std::uint32_t pid{};
    inline static std::uint32_t game_pid{};
    inline static std::mutex mtx;
};