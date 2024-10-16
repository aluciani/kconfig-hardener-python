import sys
import os

# Arrays for configs
configs_y = [
    "CONFIG_BUG","CONFIG_SLUB_DEBUG","CONFIG_THREAD_INFO_IN_TASK","CONFIG_IOMMU_SUPPORT","CONFIG_STACKPROTECTOR","CONFIG_STACKPROTECTOR_STRONG","CONFIG_STRICT_KERNEL_RWX","CONFIG_STRICT_MODULE_RWX","CONFIG_REFCOUNT_FULL","CONFIG_INIT_STACK_ALL_ZERO","CONFIG_CPU_MITIGATIONS","CONFIG_RANDOMIZE_BASE","CONFIG_VMAP_STACK","CONFIG_DEBUG_WX","CONFIG_WERROR","CONFIG_X86_MCE","CONFIG_SYN_COOKIES","CONFIG_MICROCODE","CONFIG_MICROCODE_INTEL","CONFIG_MICROCODE_AMD","CONFIG_X86_SMAP","CONFIG_X86_UMIP","CONFIG_X86_MCE_INTEL","CONFIG_X86_MCE_AMD","CONFIG_MITIGATION_RETPOLINE","CONFIG_MITIGATION_RFDS","CONFIG_MITIGATION_SPECTRE_BHI", "CONFIG_RANDOMIZE_MEMORY","CONFIG_X86_KERNEL_IBT","CONFIG_MITIGATION_PAGE_TABLE_IOLATION", "CONFIG_MITIGATION_SRSO","CONFIG_INTEL_IOMMU","CONFIG_AMD_IOMMU","CONFIG_LIST_HARDENED","CONFIG_RANDOM_KMALLOC_CACHES", "CONFIG_BUG_ON_DATA_CORRUPTION", "CONFIG_SLAB_FREELIST_HARDENED", "CONFIG_SLAB_FREELIST_RANDOM", "CONFIG_SHUFFLE_PAGE_ALLOCATOR", "CONFIG_FORTIFY_SOURCE", "CONFIG_DEBUG_LIST", "CONFIG_DEBUG_VIRTUAL", "CONFIG_DEBUG_SG", "CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "CONFIG_STATIC_USERMODEHELPER", "CONFIG_SCHED_CORE", "CONFIG_SECURITY_LOCKDOWN_LSM", "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY", "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY", "CONFIG_DEBUG_CREDENTIALS", "CONFIG_DEBUG_NOTIFIERS", "CONFIG_SCHED_STACK_END_CHECK", "CONFIG_KFENCE", "CONFIG_RANDSTRUCT_FULL", "CONFIG_HARDENED_USERCOPY","CONFIG_GCC_PLUGINS", "CONFIG_GCC_PLUGIN_LATENT_ENTROPY", "CONFIG_MODULE_SIG", "CONFIG_MODULE_SIG_ALL", "CONFIG_MODULE_SIG_SHA512", "CONFIG_INIT_ON_FREE_DEFAULT_ON", "CONFIG_EFI_DISABLE_PCI_DMA", "CONFIG_RESET_ATTACK_MITIGATION", "CONFIG_UBSAN" ,"CONFIG_UBSAN_BOUNDS", "CONFIG_UBSAN_LOCAL_BOUNDS", "CONFIG_UBSAN_TRAP", "CONFIG_UBSAN_SANITIZE_ALL", "CONFIG_GCC_PLUGIN_STACKLEAK", "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT", "CONFIG_PAGE_TABLE_CHECK", "CONFIG_PAGE_TABLE_CHECK_ENFORCED", "CONFIG_HW_RANDOM_TPM", "CONFIG_IOMMU_DEFAULT_DMA_STRICT", "CONFIG_INTEL_IOMMU_DEFAULT_ON", "CONFIG_MITIGATION_SLS", "CONFIG_INTEL_IOMMU_SVM", "CONFIG_AMD_IOMMU_V2", "CONFIG_SECURITY", "CONFIG_SECURITY_YAMA", "CONFIG_SECURITY_LANDLOCK", "CONFIG_SECURITY_SELINUX", "CONFIG_SECCOMP", "CONFIG_SECCOMP_FILTER", "CONFIG_BPF_UNPRIV_DEFAULT_OFF", "CONFIG_STRICT_DEVMEM", "CONFIG_X86_INTEL_TSX_MODE_OFF", "CONFIG_SECURITY_DMESG_RESTRICT", "CONFIG_IO_STRICT_DEVMEM", "CONFIG_TRIM_UNUSED_KSYMS", "CONFIG_X86_USER_SHADOW_STACK",
    # Add more config names from your output.md here as required...
]

configs_not_set = [
    "CONFIG_SLAB_MERGE_DEFAULT", "CONFIG_HARDENED_USERCOPY_FALLBACK", "CONFIG_HARDENED_USERCOPY_PAGESPAN", "CONFIG_STACKLEAK_METRICS", "CONFIG_STACKLEAK_RUNTIME_DISABLE", "CONFIG_IOMMU_DEFAULT_PASSTHROUGH", "CONFIG_SECURITY_SELINUX_DISABLE", "CONFIG_SECURITY_SELINUX_BOOTPARAM", "CONFIG_SECURITY_SELINUX_DEVELOP", "CONFIG_SECURITY_WRITABLE_HOOKS", "CONFIG_SECURITY_SELINUX_DEBUG", "CONFIG_ACPI_CUSTOM_METHOD", "CONFIG_COMPAT_BRK", "CONFIG_DEVKMEM", "CONFIG_BINFMT_MISC", "CONFIG_INET_DIAG", "CONFIG_KEXEC", "CONFIG_PROC_KCORE", "CONFIG_LEGACY_PTYS", "CONFIG_HIBERNATION", "CONFIG_COMPAT", "CONFIG_IA32_EMULATION", "CONFIG_X86_X32", "CONFIG_X86_X32_ABI", "CONFIG_MODIFY_LDT_SYSCALL", "CONFIG_OABI_COMPAT", "CONFIG_X86_MSR", "CONFIG_LEGACY_TIOCSTI", "CONFIG_MODULE_FORCE_LOAD", "CONFIG_DEVMEM", "CONFIG_LDISC_AUTOLOAD", "CONFIG_X86_VSYSCALL_EMULATION", "CONFIG_COMPAT_VDSO", "CONFIG_DRM_LEGACY", "CONFIG_FB", "CONFIG_VT", "CONFIG_BLK_DEV_FD", "CONFIG_BLK_DEV_FD_RAWCMD", "CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT", "CONFIG_N_GSM", "CONFIG_ZSMALLOC_STAT", "CONFIG_DEBUG_KMEMLEAK", "CONFIG_BINFMT_AOUT", "CONFIG_KPROBE_EVENTS", "CONFIG_UPROBE_EVENTS", "CONFIG_GENERIC_TRACER", "CONFIG_FUNCTION_TRACER", "CONFIG_STACK_TRACER", "CONFIG_HIST_TRIGGERS", "CONFIG_BLK_DEV_IO_TRACE", "CONFIG_PROC_VMCORE", "CONFIG_PROC_PAGE_MONITOR", "CONFIG_USELIB", "CONFIG_CHECKPOINT_RESTORE", "CONFIG_USERFAULTFD", "CONFIG_HWPOISON_INJECT", "CONFIG_MEM_SOFT_DIRTY", "CONFIG_DEVPORT", "CONFIG_DEBUG_FS", "CONFIG_NOTIFIER_ERROR_INJECTION", "CONFIG_FAIL_FUTEX", "CONFIG_PUNIT_ATOM_DEBUG", "CONFIG_ACPI_CONFIGFS", "CONFIG_EDAC_DEBUG", "CONFIG_DRM_I915_DEBUG", "CONFIG_DVB_C8SECTPFE", "CONFIG_MTD_SLRAM", "CONFIG_MTD_PHRAM", "CONFIG_IO_URING", "CONFIG_KCMP", "CONFIG_RSEQ", "CONFIG_LATENCYTOP", "CONFIG_KCOV", "CONFIG_PROVIDE_OHCI1394_DMA_INIT", "CONFIG_SUNRPC_DEBUG", "CONFIG_X86_16BIT", "CONFIG_BLK_DEV_UBLK", "CONFIG_SMB_SERVER", "CONFIG_XFS_ONLINE_SCRUB_STATS", "CONFIG_CACHESTAT_SYSCALL", "CONFIG_PREEMPTIRQ_TRACEPOINTS", "CONFIG_ENABLE_DEFAULT_TRACERS", "CONFIG_PROVE_LOCKING", "CONFIG_TEST_DEBUG_VIRTUAL", "CONFIG_MPTCP", "CONFIG_TLS", "CONFIG_TIPC", "CONFIG_IP_SCTP", "CONFIG_KGDB", "CONFIG_PTDUMP_DEBUGFS", "CONFIG_X86_PTDUMP", "CONFIG_DEBUG_CLOSURES", "CONFIG_BCACHE_CLOSURES_DEBUG", "CONFIG_STAGING", "CONFIG_KSM", "CONFIG_KALLSYMS", "CONFIG_KEXEC_FILE", "CONFIG_CRASH_DUMP", "CONFIG_USER_NS", "CONFIG_X86_CPUID", "CONFIG_X86_IOPL_IOPERM", "CONFIG_ACPI_TABLE_UPGRADE", "CONFIG_EFI_CUSTOM_SSDT_OVERLAYS", "CONFIG_AIO", "CONFIG_MAGIC_SYSRQ", "CONFIG_MAGIC_SYSRQ_SERIAL", "CONFIG_EFI_TEST", "CONFIG_MMIOTRACE_TEST", "CONFIG_KPROBES", "CONFIG_BPF_SYSCALL", "CONFIG_MMIOTRACE", "CONFIG_LIVEPATCH", "CONFIG_IP_DCCP", "CONFIG_FTRACE", "CONFIG_VIDEO_VIVID", "CONFIG_INPUT_EVBUG", "CONFIG_CORESIGHT", "CONFIG_XFS_SUPPORT_V4", "CONFIG_BLK_DEV_WRITE_MOUNTED", "CONFIG_FAULT_INJECTION", "CONFIG_ARM_PTDUMP_DEBUGFS", "CONFIG_ARM_PTDUMP", "CONFIG_SECCOMP_CACHE_DEBUG", "CONFIG_LKDTM", "CONFIG_COREDUMP", "CONFIG_RANDSTRUCT_NONE", "CONFIG_UBSAN_ENUM"
    # Add more config names from your output.md here as required...
]

# Configs that require a specific value
configs_with_values = {
    "CONFIG_KFENCE_SAMPLE_INTERVAL": "100",
    "CONFIG_DEFAULT_MMAP_MIN_ADDR": "65536",
    "CONFIG_ARCH_MMAP_RND_BITS": "32",
    # Add more config names with custom values here as required...
}

# Configs that should be added if not found
configs_to_add = [
    "CONFIG_RANDSTRUCT_FULL",
    "CONFIG_GCC_PLUGIN_LATENT_ENTROPY",
    "CONFIG_UBSAN_BOUNDS",
    "CONFIG_UBSAN_LOCAL_BOUNDS",
    "CONFIG_UBSAN_TRAP",
    "CONFIG_UBSAN_SANITIZE_ALL",
    "CONFIG_GCC_PLUGIN_STACKLEAK",
    "CONFIG_PAGE_TABLE_CHECK_ENFORCED",
]

def modify_config_file(input_path, output_path):
    # Track which configs from `configs_to_add` have been seen
    seen_configs_to_add = set()

    # Read the input config file
    with open(input_path, 'r') as infile:
        lines = infile.readlines()

    # Open the output file to write the changes
    with open(output_path, 'w') as outfile:
        for line in lines:
            modified = False

            # Strip newline for easier matching
            stripped_line = line.strip()

            # Function to check for exact match (followed by "=" or space)
            def exact_match(config, line):
                return line.startswith(f"{config}=") or line.startswith(f"# {config} is not set")

            # Check if the line matches any configs that need "y"
            for config in configs_y:
                if exact_match(config, stripped_line):
                    if f"{config}=y" not in stripped_line:
                        outfile.write(f"{config}=y\n")
                        modified = True
                    break

            # Check if the line matches any configs that need to be "not set"
            for config in configs_not_set:
                if exact_match(config, stripped_line):
                    if f"# {config} is not set" not in stripped_line:
                        outfile.write(f"# {config} is not set\n")
                        modified = True
                    break

            # Check if the line matches any configs that need a specific value
            for config, value in configs_with_values.items():
                if exact_match(config, stripped_line):
                    if f"{config}={value}" not in stripped_line:
                        outfile.write(f"{config}={value}\n")
                        modified = True
                    break

            # If no modifications were made, just write the original line
            if not modified:
                outfile.write(line)

            # Track configs that have been seen from `configs_to_add`
            for config in configs_to_add:
                if exact_match(config, stripped_line):
                    seen_configs_to_add.add(config)
                    break

        # Add any missing configs from `configs_to_add` at the end
        for config in configs_to_add:
            if config not in seen_configs_to_add:
                outfile.write(f"{config}=y\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py ./config-*.*.*-amd64")
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.isfile(input_file):
        print(f"Error: File {input_file} does not exist.")
        sys.exit(1)

    output_file = f"../NEW-{os.path.basename(input_file)}"

    modify_config_file(input_file, output_file)
    print(f"Configuration saved to {output_file}")

if __name__ == "__main__":
    main()