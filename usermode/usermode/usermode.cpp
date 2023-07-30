#include "driver.hpp" 
#define WIN32_LEAN_AND_MEAN 
#include <string>
#include <iostream>
#include <Windows.h> 

int32_t main()
{
    driver::initialize();
    const std::uint32_t pid = driver::get_pid(L"FortniteClient-Win64-Shipping.exe");
    std::cout << "[driver] game pid: " << pid << std::endl;
    driver::set_pid(pid);
    const std::uint64_t base = driver::get_modulebase(L"FortniteClient-Win64-Shipping.exe");
    std::cout << "[driver] game base: " << base << std::endl;


    std::cin.get();

}