#include "comm.hpp" 
 #include "../meme/utils.hpp" 
  
 void comm::run() { 
         update_data(); 
         if (!shared_data) { 
                 return; 
         } 
         if (!shared_data->usermode_done) { 
                 return; 
         } 
         shared_data->usermode_done = false; 
         switch (shared_data->request_type) { 
         case request_e::GET_PID: { 
                 printf("[COMM] GET_PID\n"); 
                 if (!shared_data->buffer || !shared_data->p_wstr) { 
                         break; 
                 } 
                 if (!MmIsAddressValid(shared_data->buffer)) { 
                         break; 
                 } 
                 *(std::uint32_t*)(shared_data->buffer) = utils::get_process_id_by_name(shared_data->p_wstr); 
                 break; 
         } 
         case request_e::GET_MODULEBASE: { 
                 printf("[COMM] GET_MODULEBASE\n"); 
                 if (!shared_data->pid || !shared_data->buffer || !shared_data->p_wstr) { 
                         break; 
                 } 
                 if (!MmIsAddressValid(shared_data->buffer)) { 
                         break; 
                 } 
                 PEPROCESS process{}; 
                 if (!NT_SUCCESS(PsLookupProcessByProcessId(shared_data->pid, &process))) { 
                         break; 
                 } 
                 wchar_t* ws_copy = (wchar_t*)ExAllocatePool(NonPagedPool, wcslen(shared_data->p_wstr) * sizeof(wchar_t) + sizeof(wchar_t)); 
                 if (!ws_copy) { 
                         break; 
                 } 
                 utils::memcpy((std::uint64_t)ws_copy, (std::uint64_t)shared_data->p_wstr, wcslen(shared_data->p_wstr) * sizeof(wchar_t) + sizeof(wchar_t)); 
  
                 KAPC_STATE state{}; 
                 KiStackAttachProcess(process, 1, &state); 
  
                 void* base{}; 
                 const PLIST_ENTRY list = &(PsGetProcessPeb(process)->Ldr->InLoadOrderModuleList); 
                 PLDR_DATA_TABLE_ENTRY module{}; 
                 for (PLIST_ENTRY entry = list->Flink; entry != list; 
                         module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks), entry = module->InLoadOrderLinks.Flink) { 
                         if (module == nullptr) { 
                                 continue; 
                         } 
                         if (module->BaseDllName.Length > 0 && 
                                 _wcsnicmp(module->BaseDllName.Buffer, ws_copy, module->BaseDllName.Length) == 0) { 
                                 base = module->DllBase; 
                                 break; 
                         } 
                 } 
                 KiUnstackDetachProcess(&state, 1); 
                 ExFreePool(ws_copy); 
                 *(void**)(shared_data->buffer) = base; 
                 break; 
         } 
         case request_e::READ_MEM: { 
                 printf("[COMM] READ_MEM\n"); 
                 if (!shared_data->pid || !utils::is_valid(shared_data->address) || !shared_data->buffer || !shared_data->size) { 
                         break; 
                 } 
                 PEPROCESS process{}; 
                 if (!NT_SUCCESS(PsLookupProcessByProcessId(shared_data->pid, &process))) { 
                         break; 
                 } 
                 utils::copy_virtual_memory(process, shared_data->address, comm_process, shared_data->buffer, shared_data->size); 
                 break; 
         } 
         case request_e::WRITE_MEM: { 
                 printf("[COMM] WRITE_MEM\n"); 
                 if (!shared_data->pid || !utils::is_valid(shared_data->address) || !shared_data->buffer || !shared_data->size) { 
                         break; 
                 } 
                 PEPROCESS process{}; 
                 if (!NT_SUCCESS(PsLookupProcessByProcessId(shared_data->pid, &process))) { 
                         break; 
                 } 
                 utils::copy_virtual_memory(comm_process, shared_data->buffer, process, shared_data->address, shared_data->size); 
                 break; 
         } 
         case request_e::DISCONNECT: 
                 printf("[COMM] DISCONNECT\n"); 
                 shared_data->kernelmode_done = true; 
                 shared_data = nullptr; 
                 return; 
         case request_e::NONE: 
         default: 
                 break; 
         } 
         shared_data->kernelmode_done = true; 
 } 
  
 void comm::update_data() { 
         if (!MmIsAddressValid((void*)p_comm_address)) { 
                 shared_data = nullptr; 
                 const std::uint32_t pid = utils::get_process_id_by_name(skCrypt(L"usermode.exe")); // shit way of doing this, you can also pass the process name into driverentry or scan ALL processes which is also shit 
                 if (!pid) { 
                         return; 
                 } 
                 printf("[COMM] pid: %lu\n", pid); 
                 comm_process = nullptr; 
                 if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &comm_process))) { 
                         return; 
                 } 
                 printf("[COMM] comm_process: %p\n", comm_process); 
                 const std::uint64_t comm_process_base = (std::uint64_t)PsGetProcessSectionBaseAddress(comm_process); 
                 if (!comm_process_base) { 
                         return; 
                 } 
                 printf("[COMM] comm_process_base: %llx\n", comm_process_base); 
                 KAPC_STATE state{}; 
                 KiStackAttachProcess(comm_process, 1, &state); 
                 p_comm_address = find_comm_ptr(comm_process_base); 
                 printf("[COMM] p_comm_address: %llx\n", p_comm_address); 
                 if (!MmIsAddressValid((void*)p_comm_address)) { 
                         return; 
                 } 
                 *(std::uint64_t*)p_comm_address = confirm; 
         } 
         if (shared_data && !MmIsAddressValid((void*)shared_data)) { 
                 printf("[COMM] case2\n"); 
                 shared_data = nullptr; 
                 return; 
         } 
         if (!shared_data) { 
                 void* comm_address = *(void**)p_comm_address; 
                 if (comm_address != (void*)confirm && MmIsAddressValid(comm_address)) { 
                         printf("[COMM] comm_address: %p\n", comm_address); 
                         shared_data = *(shared_data_t**)comm_address; 
                         *(std::uint64_t*)(p_comm_address) = confirm; 
                         shared_data->usermode_done = false; 
                         shared_data->kernelmode_done = true; 
                 } 
                 else if (comm_address != (void*)confirm) { 
                         *(std::uint64_t*)(p_comm_address) = confirm; 
                 } 
         } 
 } 
 std::uint64_t comm::find_comm_ptr(const std::uint64_t& base) { 
         const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base; 
         const PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((std::uint8_t*)dos_header + dos_header->e_lfanew); 
         PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header); 
         for (std::uint16_t i = 1; i < nt_header->FileHeader.NumberOfSections; i++, section++) { 
                 if ((section->Characteristics & IMAGE_SCN_MEM_READ) && (section->Characteristics & IMAGE_SCN_MEM_WRITE) && 
                         !(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) { 
                         for (std::uint64_t current_address = base + section->VirtualAddress; 
                                 current_address < base + section->VirtualAddress + section->Misc.VirtualSize; current_address++) { 
                                 if (*(magic_sig_t*)current_address == magic_signature) { 
                                         return current_address + sizeof(magic_sig_t); 
                                 } 
                         } 
                 } 
         } 
         return 0; 
 }