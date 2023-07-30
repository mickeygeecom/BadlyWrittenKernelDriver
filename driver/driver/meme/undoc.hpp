#pragma once 
  
 // functions 
 extern "C" NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength); 
 extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process); 
 extern "C" PPEB PsGetProcessPeb(PEPROCESS Process); 
 inline char(__fastcall* KiStackAttachProcess)(PEPROCESS process, char bitflag, PKAPC_STATE apc_state) = nullptr; 
 inline __int64(__fastcall* KiUnstackDetachProcess)(PKAPC_STATE apc_state, int bitflag) = nullptr; 
  
 // enums 
 enum _SYSTEM_INFORMATION_CLASS { 
     SystemBasicInformation = 0, 
     SystemProcessorInformation = 1, 
     SystemPerformanceInformation = 2, 
     SystemTimeOfDayInformation = 3, 
     SystemPathInformation = 4, 
     SystemProcessInformation = 5, 
     SystemCallCountInformation = 6, 
     SystemDeviceInformation = 7, 
     SystemProcessorPerformanceInformation = 8, 
     SystemFlagsInformation = 9, 
     SystemCallTimeInformation = 10, 
     SystemModuleInformation = 11, 
     SystemLocksInformation = 12, 
     SystemStackTraceInformation = 13, 
     SystemPagedPoolInformation = 14, 
     SystemNonPagedPoolInformation = 15, 
     SystemHandleInformation = 16, 
     SystemObjectInformation = 17, 
     SystemPageFileInformation = 18, 
     SystemVdmInstemulInformation = 19, 
     SystemVdmBopInformation = 20, 
     SystemFileCacheInformation = 21, 
     SystemPoolTagInformation = 22, 
     SystemInterruptInformation = 23, 
     SystemDpcBehaviorInformation = 24, 
     SystemFullMemoryInformation = 25, 
     SystemLoadGdiDriverInformation = 26, 
     SystemUnloadGdiDriverInformation = 27, 
     SystemTimeAdjustmentInformation = 28, 
     SystemSummaryMemoryInformation = 29, 
     SystemMirrorMemoryInformation = 30, 
     SystemPerformanceTraceInformation = 31, 
     SystemObsolete0 = 32, 
     SystemExceptionInformation = 33, 
     SystemCrashDumpStateInformation = 34, 
     SystemKernelDebuggerInformation = 35, 
     SystemContextSwitchInformation = 36, 
     SystemRegistryQuotaInformation = 37, 
     SystemExtendServiceTableInformation = 38, 
     SystemPrioritySeperation = 39, 
     SystemVerifierAddDriverInformation = 40, 
     SystemVerifierRemoveDriverInformation = 41, 
     SystemProcessorIdleInformation = 42, 
     SystemLegacyDriverInformation = 43, 
     SystemCurrentTimeZoneInformation = 44, 
     SystemLookasideInformation = 45, 
     SystemTimeSlipNotification = 46, 
     SystemSessionCreate = 47, 
     SystemSessionDetach = 48, 
     SystemSessionInformation = 49, 
     SystemRangeStartInformation = 50, 
     SystemVerifierInformation = 51, 
     SystemVerifierThunkExtend = 52, 
     SystemSessionProcessInformation = 53, 
     SystemLoadGdiDriverInSystemSpace = 54, 
     SystemNumaProcessorMap = 55, 
     SystemPrefetcherInformation = 56, 
     SystemExtendedProcessInformation = 57, 
     SystemRecommendedSharedDataAlignment = 58, 
     SystemComPlusPackage = 59, 
     SystemNumaAvailableMemory = 60, 
     SystemProcessorPowerInformation = 61, 
     SystemEmulationBasicInformation = 62, 
     SystemEmulationProcessorInformation = 63, 
     SystemExtendedHandleInformation = 64, 
     SystemLostDelayedWriteInformation = 65, 
     SystemBigPoolInformation = 66, 
     SystemSessionPoolTagInformation = 67, 
     SystemSessionMappedViewInformation = 68, 
     SystemHotpatchInformation = 69, 
     SystemObjectSecurityMode = 70, 
     SystemWatchdogTimerHandler = 71, 
     SystemWatchdogTimerInformation = 72, 
     SystemLogicalProcessorInformation = 73, 
     SystemWow64SharedInformationObsolete = 74, 
     SystemRegisterFirmwareTableInformationHandler = 75, 
     SystemFirmwareTableInformation = 76, 
     SystemModuleInformationEx = 77, 
     SystemVerifierTriageInformation = 78, 
     SystemSuperfetchInformation = 79, 
     SystemMemoryListInformation = 80, 
     SystemFileCacheInformationEx = 81, 
     SystemThreadPriorityClientIdInformation = 82, 
     SystemProcessorIdleCycleTimeInformation = 83, 
     SystemVerifierCancellationInformation = 84, 
     SystemProcessorPowerInformationEx = 85, 
     SystemRefTraceInformation = 86, 
     SystemSpecialPoolInformation = 87, 
     SystemProcessIdInformation = 88, 
     SystemErrorPortInformation = 89, 
     SystemBootEnvironmentInformation = 90, 
     SystemHypervisorInformation = 91, 
     SystemVerifierInformationEx = 92, 
     SystemTimeZoneInformation = 93, 
     SystemImageFileExecutionOptionsInformation = 94, 
     SystemCoverageInformation = 95, 
     SystemPrefetchPatchInformation = 96, 
     SystemVerifierFaultsInformation = 97, 
     SystemSystemPartitionInformation = 98, 
     SystemSystemDiskInformation = 99, 
     SystemProcessorPerformanceDistribution = 100, 
     SystemNumaProximityNodeInformation = 101, 
     SystemDynamicTimeZoneInformation = 102, 
     SystemCodeIntegrityInformation = 103, 
     SystemProcessorMicrocodeUpdateInformation = 104, 
     SystemProcessorBrandString = 105, 
     SystemVirtualAddressInformation = 106, 
     SystemLogicalProcessorAndGroupInformation = 107, 
     SystemProcessorCycleTimeInformation = 108, 
     SystemStoreInformation = 109, 
     SystemRegistryAppendString = 110, 
     SystemAitSamplingValue = 111, 
     SystemVhdBootInformation = 112, 
     SystemCpuQuotaInformation = 113, 
     SystemNativeBasicInformation = 114, 
     SystemErrorPortTimeouts = 115, 
     SystemLowPriorityIoInformation = 116, 
     SystemBootEntropyInformation = 117, 
     SystemVerifierCountersInformation = 118, 
     SystemPagedPoolInformationEx = 119, 
     SystemSystemPtesInformationEx = 120, 
     SystemNodeDistanceInformation = 121, 
     SystemAcpiAuditInformation = 122, 
     SystemBasicPerformanceInformation = 123, 
     SystemQueryPerformanceCounterInformation = 124, 
     SystemSessionBigPoolInformation = 125, 
     SystemBootGraphicsInformation = 126, 
     SystemScrubPhysicalMemoryInformation = 127, 
     SystemBadPageInformation = 128, 
     SystemProcessorProfileControlArea = 129, 
     SystemCombinePhysicalMemoryInformation = 130, 
     SystemEntropyInterruptTimingInformation = 131, 
     SystemConsoleInformation = 132, 
     SystemPlatformBinaryInformation = 133, 
     SystemPolicyInformation = 134, 
     SystemHypervisorProcessorCountInformation = 135, 
     SystemDeviceDataInformation = 136, 
     SystemDeviceDataEnumerationInformation = 137, 
     SystemMemoryTopologyInformation = 138, 
     SystemMemoryChannelInformation = 139, 
     SystemBootLogoInformation = 140, 
     SystemProcessorPerformanceInformationEx = 141, 
     SystemCriticalProcessErrorLogInformation = 142, 
     SystemSecureBootPolicyInformation = 143, 
     SystemPageFileInformationEx = 144, 
     SystemSecureBootInformation = 145, 
     SystemEntropyInterruptTimingRawInformation = 146, 
     SystemPortableWorkspaceEfiLauncherInformation = 147, 
     SystemFullProcessInformation = 148, 
     SystemKernelDebuggerInformationEx = 149, 
     SystemBootMetadataInformation = 150, 
     SystemSoftRebootInformation = 151, 
     SystemElamCertificateInformation = 152, 
     SystemOfflineDumpConfigInformation = 153, 
     SystemProcessorFeaturesInformation = 154, 
     SystemRegistryReconciliationInformation = 155, 
     SystemEdidInformation = 156, 
     SystemManufacturingInformation = 157, 
     SystemEnergyEstimationConfigInformation = 158, 
     SystemHypervisorDetailInformation = 159, 
     SystemProcessorCycleStatsInformation = 160, 
     SystemVmGenerationCountInformation = 161, 
     SystemTrustedPlatformModuleInformation = 162, 
     SystemKernelDebuggerFlags = 163, 
     SystemCodeIntegrityPolicyInformation = 164, 
     SystemIsolatedUserModeInformation = 165, 
     SystemHardwareSecurityTestInterfaceResultsInformation = 166, 
     SystemSingleModuleInformation = 167, 
     SystemAllowedCpuSetsInformation = 168, 
     SystemVsmProtectionInformation = 169, 
     SystemInterruptCpuSetsInformation = 170, 
     SystemSecureBootPolicyFullInformation = 171, 
     SystemCodeIntegrityPolicyFullInformation = 172, 
     SystemAffinitizedInterruptProcessorInformation = 173, 
     SystemRootSiloInformation = 174, 
     SystemCpuSetInformation = 175, 
     SystemCpuSetTagInformation = 176, 
     SystemWin32WerStartCallout = 177, 
     SystemSecureKernelProfileInformation = 178, 
     SystemCodeIntegrityPlatformManifestInformation = 179, 
     SystemInterruptSteeringInformation = 180, 
     SystemSupportedProcessorArchitectures = 181, 
     SystemMemoryUsageInformation = 182, 
     SystemCodeIntegrityCertificateInformation = 183, 
     SystemPhysicalMemoryInformation = 184, 
     SystemControlFlowTransition = 185, 
     SystemKernelDebuggingAllowed = 186, 
     SystemActivityModerationExeState = 187, 
     SystemActivityModerationUserSettings = 188, 
     SystemCodeIntegrityPoliciesFullInformation = 189, 
     SystemCodeIntegrityUnlockInformation = 190, 
     SystemIntegrityQuotaInformation = 191, 
     SystemFlushInformation = 192, 
     SystemProcessorIdleMaskInformation = 193, 
     SystemSecureDumpEncryptionInformation = 194, 
     SystemWriteConstraintInformation = 195, 
     SystemKernelVaShadowInformation = 196, 
     SystemHypervisorSharedPageInformation = 197, 
     SystemFirmwareBootPerformanceInformation = 198, 
     SystemCodeIntegrityVerificationInformation = 199, 
     SystemFirmwarePartitionInformation = 200, 
     SystemSpeculationControlInformation = 201, 
     SystemDmaGuardPolicyInformation = 202, 
     SystemEnclaveLaunchControlInformation = 203, 
     SystemWorkloadAllowedCpuSetsInformation = 204, 
     SystemCodeIntegrityUnlockModeInformation = 205, 
     SystemLeapSecondInformation = 206, 
     SystemFlags2Information = 207, 
     SystemSecurityModelInformation = 208, 
     SystemCodeIntegritySyntheticCacheInformation = 209, 
     SystemFeatureConfigurationInformation = 210, 
     SystemFeatureConfigurationSectionInformation = 211, 
     SystemFeatureUsageSubscriptionInformation = 212, 
     SystemSecureSpeculationControlInformation = 213, 
     SystemSpacesBootInformation = 214, 
     SystemFwRamdiskInformation = 215, 
     SystemWheaIpmiHardwareInformation = 216, 
     SystemDifSetRuleClassInformation = 217, 
     SystemDifClearRuleClassInformation = 218, 
     SystemDifApplyPluginVerificationOnDriver = 219, 
     SystemDifRemovePluginVerificationOnDriver = 220, 
     SystemShadowStackInformation = 221, 
     SystemBuildVersionInformation = 222, 
     SystemPoolLimitInformation = 223, 
     SystemCodeIntegrityAddDynamicStore = 224, 
     SystemCodeIntegrityClearDynamicStores = 225, 
     SystemPoolZeroingInformation = 227, 
     MaxSystemInfoClass = 228 
 }; 
 typedef enum _KTHREAD_STATE { 
     Initialized, 
     Ready, 
     Running, 
     Standby, 
     Terminated, 
     Waiting, 
     Transition, 
     DeferredReady, 
     GateWaitObsolete, 
     WaitingForProcessInSwap, 
     MaximumThreadState 
 } KTHREAD_STATE, * PKTHREAD_STATE; 
  
 // structs 
 typedef struct _RTL_PROCESS_MODULE_INFORMATION 
 { 
     HANDLE Section; 
     PVOID MappedBase; 
     PVOID ImageBase; 
     ULONG ImageSize; 
     ULONG Flags; 
     USHORT LoadOrderIndex; 
     USHORT InitOrderIndex; 
     USHORT LoadCount; 
     USHORT OffsetToFileName; 
     UCHAR  FullPathName[256]; 
 } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION; 
 typedef struct _RTL_PROCESS_MODULES 
 { 
     ULONG NumberOfModules; 
     RTL_PROCESS_MODULE_INFORMATION Modules[1]; 
 } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES; 
 typedef struct _PEB_LDR_DATA { 
     ULONG Length; 
     UCHAR Initialized; 
     PVOID SsHandle; 
     LIST_ENTRY InLoadOrderModuleList; 
     LIST_ENTRY InMemoryOrderModuleList; 
     LIST_ENTRY InInitializationOrderModuleList; 
 } PEB_LDR_DATA, *PPEB_LDR_DATA; 
 typedef struct _LDR_DATA_TABLE_ENTRY { 
     LIST_ENTRY InLoadOrderLinks; 
     LIST_ENTRY InMemoryOrderLinks; 
     LIST_ENTRY InInitializationOrderLinks; 
     PVOID DllBase; 
     PVOID EntryPoint; 
     ULONG SizeOfImage; 
     UNICODE_STRING FullDllName; 
     UNICODE_STRING BaseDllName; 
     ULONG Flags; 
     USHORT LoadCount; 
     USHORT TlsIndex; 
     LIST_ENTRY HashLinks; 
     ULONG TimeDateStamp; 
 } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY; 
 typedef struct _PEB { 
     UCHAR InheritedAddressSpace; 
     UCHAR ReadImageFileExecOptions; 
     UCHAR BeingDebugged; 
     UCHAR BitField; 
     PVOID Mutant; 
     PVOID ImageBaseAddress; 
     PPEB_LDR_DATA Ldr; 
     PVOID ProcessParameters; 
     PVOID SubSystemData; 
     PVOID ProcessHeap; 
     PVOID FastPebLock; 
     PVOID AtlThunkSListPtr; 
     PVOID IFEOKey; 
     PVOID CrossProcessFlags; 
     PVOID KernelCallbackTable; 
     ULONG SystemReserved; 
     ULONG AtlThunkSListPtr32; 
     PVOID ApiSetMap; 
 } PEB, *PPEB; 
 typedef struct _SYSTEM_THREAD_INFORMATION { 
     LARGE_INTEGER KernelTime; 
     LARGE_INTEGER UserTime; 
     LARGE_INTEGER CreateTime; 
     ULONG WaitTime; 
     PVOID StartAddress; 
     CLIENT_ID ClientId; 
     KPRIORITY Priority; 
     LONG BasePriority; 
     ULONG ContextSwitches; 
     KTHREAD_STATE ThreadState; 
     KWAIT_REASON WaitReason; 
 } SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION; 
 typedef struct _SYSTEM_PROCESS_INFORMATION { 
     ULONG NextEntryOffset; 
     ULONG NumberOfThreads; 
     LARGE_INTEGER WorkingSetPrivateSize; // since VISTA 
     ULONG HardFaultCount; // since WIN7 
     ULONG NumberOfThreadsHighWatermark; // since WIN7 
     ULONGLONG CycleTime; // since WIN7 
     LARGE_INTEGER CreateTime; 
     LARGE_INTEGER UserTime; 
     LARGE_INTEGER KernelTime; 
     UNICODE_STRING ImageName; 
     KPRIORITY BasePriority; 
     HANDLE UniqueProcessId; 
     HANDLE InheritedFromUniqueProcessId; 
     ULONG HandleCount; 
     ULONG SessionId; 
     ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation) 
     SIZE_T PeakVirtualSize; 
     SIZE_T VirtualSize; 
     ULONG PageFaultCount; 
     SIZE_T PeakWorkingSetSize; 
     SIZE_T WorkingSetSize; 
     SIZE_T QuotaPeakPagedPoolUsage; 
     SIZE_T QuotaPagedPoolUsage; 
     SIZE_T QuotaPeakNonPagedPoolUsage; 
     SIZE_T QuotaNonPagedPoolUsage; 
     SIZE_T PagefileUsage; 
     SIZE_T PeakPagefileUsage; 
     SIZE_T PrivatePageCount; 
     LARGE_INTEGER ReadOperationCount; 
     LARGE_INTEGER WriteOperationCount; 
     LARGE_INTEGER OtherOperationCount; 
     LARGE_INTEGER ReadTransferCount; 
     LARGE_INTEGER WriteTransferCount; 
     LARGE_INTEGER OtherTransferCount; 
     SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation 
 } SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;