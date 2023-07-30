#include "driver.hpp" 
#define WIN32_LEAN_AND_MEAN 
#include <string>
#include <iostream>
#include <Windows.h> 

#pragma optimize("", off) 
void driver::initialize() {
    mtx.lock();

    while (comm.comm_ptr != (shared_data_t**)confirm) {}
    pid = GetCurrentProcessId();
    shared_data = new shared_data_t();
    comm.comm_ptr = &shared_data;
    send_request();
    memset(&comm.magic_signature, 0, sizeof(comm.magic_signature));

    mtx.unlock();

    
}
#pragma optimize("", on) 
void driver::set_pid(const std::uint32_t pid) {
    game_pid = pid;
}
std::uint32_t driver::get_pid(const wchar_t* process_name) {
    mtx.lock();

    std::uint32_t buffer{};
    shared_data->request_type = request_e::GET_PID;
    shared_data->buffer = &buffer;
    shared_data->p_wstr = process_name;
    send_request();

    mtx.unlock();
    return buffer;
}
std::uint64_t driver::get_modulebase(const wchar_t* module_name, const std::uint32_t pid) {
    mtx.lock();

    std::uint64_t base{};
    shared_data->request_type = request_e::GET_MODULEBASE;
    shared_data->pid = (void*)pid;
    shared_data->buffer = &base;
    shared_data->p_wstr = module_name;
    send_request();

    mtx.unlock();
    return base;
}
void driver::read_memory(void* address, void* buffer, const std::size_t size) {
    mtx.lock();

    shared_data->request_type = request_e::READ_MEM;
    shared_data->pid = (void*)game_pid;
    shared_data->address = address;
    shared_data->buffer = buffer;
    shared_data->size = size;
    send_request();

    mtx.unlock();
}
void driver::write_memory(void* address, void* buffer, std::size_t size) {
    mtx.lock();

    shared_data->request_type = request_e::WRITE_MEM;
    shared_data->pid = (void*)game_pid;
    shared_data->address = address;
    shared_data->buffer = buffer;
    shared_data->size = size;
    send_request();

    mtx.unlock();
}
void driver::disconnect() {
    mtx.lock();
    shared_data->request_type = request_e::DISCONNECT;
    send_request();

    delete shared_data;
    mtx.unlock();
}

#pragma optimize("", off) 
void driver::send_request() {
    shared_data->kernelmode_done = false;
    shared_data->usermode_done = true;
    while (!shared_data->kernelmode_done) {}
}
#pragma optimize("", on)