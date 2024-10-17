This python script modify the linux kernel config to automatically remove/add some useless/usefull options based on https://github.com/a13xp0p0v/kernel-hardening-checker script
This python script is intended for a 12 (CONFIG_NR_CPUS=12) recent (CONFIG_MCORE2) core processor. It is intended for Intel :
CONFIG_X86_MCE_AMD, CONFIG_AMD_NUMA ,CONFIG_AMD_IOMMU, CONFIG_AMD_IOMMU_V2 ,CONFIG_KVM_AMD, CONFIG_PERF_EVENTS_AMD_UNCORE, CONFIG_AMD_MEM_ENCRYPT, CONFIG_X86_AMD_FREQ_SENSITIVITY ,CONFIG_PERF_EVENTS_AMD_POWER will be "is not set"

EFI will be disable, only letting Legacy booting (CONFIG_EFI)

BBR algorithm will be set as default TCP congestion handling (CONFIG_TCP_CONG_BBR, CONFIG_DEFAULT_BBR)

Other security option will be set ON and other option will be turned OFF to ensure maximum security.
Please check the script before using it and applying the config to kernel.
