#include "meme.hpp" 
 #include "../comm/comm.hpp" 
 #include "utils.hpp" 
  
 NTSTATUS meme::setup(const std::uint64_t mdl) { 
         printf("[MEME] setup called\n"); 
         if (mdl) { 
                 if (!null_pfn((PMDL)mdl)) { 
                         printf("[MEME] failed to clear pfn\n"); 
                         return STATUS_UNSUCCESSFUL; 
                 } 
                 printf("[MEME] cleared pfn\n"); 
         } 
         else { 
                 printf("[MEME] [WARN] not using Mdl memory\n"); 
         } 
         void* ntoskrnl = utils::get_driver_base(skCrypt("ntoskrnl.exe")); 
         if (!ntoskrnl) { 
                 printf("[MEME] ntoskrnl invalid\n"); 
                 return STATUS_UNSUCCESSFUL; 
         } 
         printf("[MEME] ntoskrnl: %p\n", ntoskrnl); 
         void* ki_stack_attach_process = utils::find_pattern((char*)ntoskrnl, skCrypt("\xE8\x00\x00\x00\x00\x44\x8A\xED"), skCrypt("x????xxx")); 
         if (!ki_stack_attach_process) { 
                 printf("[MEME] ki_stack_attach_process invalid\n"); 
                 return STATUS_UNSUCCESSFUL; 
         } 
         KiStackAttachProcess = (decltype(KiStackAttachProcess))utils::rva((std::uint8_t*)ki_stack_attach_process, 5); 
         if (!KiStackAttachProcess) { 
                 printf("[MEME] KiStackAttachProcess invalid\n"); 
                 return STATUS_UNSUCCESSFUL; 
         } 
         printf("[MEME] KiStackAttachProcess: %p\n", KiStackAttachProcess); 
         void* ki_unstack_dettach_process = utils::find_pattern((char*)ntoskrnl, skCrypt("\xE8\x00\x00\x00\x00\x89\x77\x08"), skCrypt("x????xxx")); 
         if (!ki_unstack_dettach_process) { 
                 printf("[MEME] ki_unstack_dettach_process invalid\n"); 
                 return STATUS_UNSUCCESSFUL; 
         } 
         KiUnstackDetachProcess = (decltype(KiUnstackDetachProcess))utils::rva((std::uint8_t*)ki_unstack_dettach_process, 5); 
         if (!KiUnstackDetachProcess) { 
                 printf("[MEME] KiUnstackDetachProcess invalid\n"); 
                 return STATUS_UNSUCCESSFUL; 
         } 
         printf("[MEME] KiUnstackDetachProcess: %p\n", KiUnstackDetachProcess); 
         HANDLE thread{}; 
         NTSTATUS status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)meme::thread, NULL); 
         printf("[MEME] done\n"); 
  
         return status; 
 } 
 void meme::thread() { 
         while (true) { 
                 comm::run(); 
         } 
 } 
  
 bool meme::null_pfn(PMDL mdl) { 
         PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl); 
         if (!mdl_pages) { 
                 return false; 
         } 
         const std::uint32_t mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl)); 
         std::uint32_t null_pfn = 0x0; 
         MM_COPY_ADDRESS source_address{}; 
         source_address.VirtualAddress = &null_pfn; 
         for (std::uint32_t i = 0; i < mdl_page_count; i++) { 
                 std::size_t out_bytes{}; 
                 MmCopyMemory(&mdl_pages[i], source_address, sizeof(std::uint32_t), MM_COPY_MEMORY_VIRTUAL, &out_bytes); 
         } 
         return true; 
 }