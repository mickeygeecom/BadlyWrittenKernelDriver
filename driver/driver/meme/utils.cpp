#include "utils.hpp" 
  
 void* utils::get_driver_base(const char* mod_name) { 
         ULONG size{}; 
         NTSTATUS status{}; 
         ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size); 
         if (!size) { 
                 return 0; 
         } 
         PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size); 
         if (!modules) { 
                 return 0; 
         } 
         status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, nullptr); 
         if (!NT_SUCCESS(status)) { 
                 ExFreePool(modules); 
                 return 0; 
         } 
  
         PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules; 
         void* base{}; 
         for (ULONG i = 0; i < modules->NumberOfModules; i++) { 
                 if (strstr((char*)module[i].FullPathName, mod_name)) { 
                         base = module[i].ImageBase; 
                         break; 
                 } 
         } 
  
         ExFreePool(modules); 
         return base; 
 } 
 void* utils::find_pattern(char* base, char* pattern, char* mask) { 
         void* match = 0; 
         PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew); 
         PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers); 
         for (std::uint32_t i = 0; i < headers->FileHeader.NumberOfSections; ++i) { 
                 PIMAGE_SECTION_HEADER section = &sections[i]; 
                 if (*(int*)section->Name == 'EGAP' || memcmp(section->Name, skCrypt(".text"), 5) == 0) { 
                         match = find_pattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask); 
                         if (match) { 
                                 break; 
                         } 
                 } 
         } 
         return match; 
 } 
 std::uint64_t utils::rva(std::uint8_t* address, std::uint64_t size) { 
         return (std::uint64_t)((std::uint8_t*)(address + *(int*)(address + (size - 4)) + size)); 
 } 
 std::uint32_t utils::get_process_id_by_name(const wchar_t* process_name) { 
         ULONG size{}; 
         NTSTATUS status{}; 
         ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &size); 
         if (!size) { 
                 return 0; 
         } 
         void* buffer = ExAllocatePool(NonPagedPool, size); 
         if (!buffer) { 
                 return 0; 
         } 
         PSYSTEM_PROCESS_INFORMATION process_information = (PSYSTEM_PROCESS_INFORMATION)buffer; 
         status = ZwQuerySystemInformation(SystemProcessInformation, process_information, size, nullptr); 
         if (!NT_SUCCESS(status)) { 
                 ExFreePool(buffer); 
                 return 0; 
         } 
         for (std::uint32_t pid = (std::uint32_t)process_information->UniqueProcessId; process_information->NextEntryOffset; 
                 process_information = (PSYSTEM_PROCESS_INFORMATION)((std::uint8_t*)process_information + process_information->NextEntryOffset), 
                 pid = (std::uint32_t)process_information->UniqueProcessId) { 
                 if (process_information->ImageName.Length > 0 && 
                         _wcsnicmp(process_information->ImageName.Buffer, process_name, process_information->ImageName.Length) == 0) { 
                         ExFreePool(buffer); 
                         return pid; 
                 } 
         } 
         ExFreePool(buffer); 
         return 0; 
 } 
 void utils::memcpy(std::uint64_t destination, std::uint64_t source, std::size_t size) { 
         while (true) { 
                 if (size >= 8) { 
                         *(std::uint64_t*)destination = *(std::uint64_t*)source; 
                         destination += 8; 
                         source += 8; 
                         size -= 8; 
                 } 
                 else if (size >= 4) { 
                         *(std::uint32_t*)destination = *(std::uint32_t*)source; 
                         destination += 4; 
                         source += 4; 
                         size -= 4; 
                 } 
                 else if (size >= 2) { 
                         *(std::uint16_t*)destination = *(std::uint16_t*)source; 
                         destination += 2; 
                         source += 2; 
                         size -= 2; 
                 } 
                 else if (size) { 
                         *(std::uint8_t*)destination = *(std::uint8_t*)source; 
                         source++; 
                         size--; 
                 } 
                 else { 
                         break; 
                 } 
         } 
 } 
 bool utils::is_valid(void* ptr) { 
         constexpr std::uint64_t min = 0x0001000; 
         constexpr std::uint64_t max = 0x7FFFFFFEFFFF; 
         return ((std::uint64_t)ptr > min && (std::uint64_t)ptr < max); 
 } 
 bool utils::copy_virtual_memory(PEPROCESS source_process, void* source_address, PEPROCESS target_process, void* target_address, std::size_t size) { 
         void* buffer = ExAllocatePool(NonPagedPool, size); 
         if (!buffer) { 
                 return false; 
         } 
         KAPC_STATE source_state{}; 
         KiStackAttachProcess(source_process, 1, &source_state); 
         if (!MmIsAddressValid((void*)source_address)) { 
                 KiUnstackDetachProcess(&source_state, 1); 
                 ExFreePool(buffer); 
                 return false; 
         } 
         utils::memcpy((std::uint64_t)buffer, (std::uint64_t)source_address, size); 
         KiUnstackDetachProcess(&source_state, 1); 
  
         KAPC_STATE target_state{}; 
         KiStackAttachProcess(target_process, 1, &target_state); 
         if (!MmIsAddressValid((void*)target_address)) { 
                 KiUnstackDetachProcess(&target_state, 1); 
                 ExFreePool(buffer); 
                 return false; 
         } 
         utils::memcpy((std::uint64_t)target_address, (std::uint64_t)buffer, size); 
         KiUnstackDetachProcess(&target_state, 1); 
         ExFreePool(buffer); 
         return true; 
 } 
  
 void* utils::find_pattern(char* base, std::uint32_t length, char* pattern, char* mask) { 
         length -= (std::uint32_t)strlen(mask); 
         for (std::uint32_t i = 0; i <= length; ++i) { 
                 void* addr = &base[i]; 
                 if (check_mask((char*)addr, pattern, mask)) { 
                         return addr; 
                 } 
         } 
         return 0; 
 } 
 bool utils::check_mask(char* base, char* pattern, char* mask) { 
         for (; *mask; ++base, ++pattern, ++mask) { 
                 if (*mask == 'x' && *base != *pattern) { 
                         return false; 
                 } 
         } 
         return true; 
 }