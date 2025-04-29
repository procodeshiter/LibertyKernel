#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <CommonCrypto/CommonDigest.h>

#define KERNEL_SEARCH_START  0xfffffff000000000
#define TRUSTCACHE_MAGIC     0x7472756365737463

typedef struct {
    uint64_t next;
    uint64_t prev;
} trustcache_entry_list;

typedef struct {
    uint64_t next;
    uint64_t prev;
    uint64_t this;
    uint64_t uuid;
    uint32_t version;
    uint32_t length;
    uint64_t data;
} trustcache_module;
static task_t kernel_task = MACH_PORT_NULL;
static uint64_t kernel_slide = 0;
static uint64_t trustcache_addr = 0;

kern_return_t kernel_read(uint64_t addr, void *data, size_t size) {
    mach_vm_size_t outsize = size;
    return mach_vm_read_overwrite(kernel_task, addr, size, (mach_vm_address_t)data, &outsize);
}
kern_return_t kernel_write(uint64_t addr, const void *data, size_t size) {
    return mach_vm_write(kernel_task, addr, (vm_offset_t)data, (mach_msg_type_number_t)size);
}

uint64_t kalloc(size_t size) {
    mach_vm_address_t addr = 0;
    mach_vm_allocate(kernel_task, &addr, size, VM_FLAGS_ANYWHERE);
    return addr;
}
uint64_t find_kernel_base() {
    size_t size = 0;
    void *ptr = NULL;
    int mib[4] = {CTL_KERN, KERN_STRUCTINFO, KERN_STRUCTINFO_KERNEL, 0};
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != -1) {
        ptr = malloc(size);
        if (sysctl(mib, 4, ptr, &size, NULL, 0) != -1) {
            uint64_t base = *(uint64_t *)(ptr + 0x10);
            free(ptr);
            return base;
        }
        free(ptr);
    }
    for (uint64_t addr = KERNEL_SEARCH_START; addr < KERNEL_SEARCH_START + 0x2000000; addr += 0x1000) {
        uint32_t magic = 0;
        kernel_read(addr, &magic, sizeof(magic));
        if (magic == 0xFEEDFACF) {
            return addr;
        }
    }
    return 0;
}

uint64_t find_trustcache() {
    uint64_t kernel_base = find_kernel_base();
    kernel_slide = kernel_base - 0xFFFFFFF007004000;
    uint8_t sig[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x63, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x63};
    for (uint64_t addr = kernel_base; addr < kernel_base + 0x2000000; addr += 8) {
        uint8_t buf[24];
        kernel_read(addr, buf, sizeof(buf));
        if (memcmp(buf, sig, sizeof(sig)) == 0) {
            return addr + 0x10;
        }
    }
    return 0;
}
void generate_cdhash(const char *path, uint8_t *cdhash) {
    NSData *fileData = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:path]];
    if (!fileData) return;
    CC_SHA1(fileData.bytes, (CC_LONG)fileData.length, cdhash);
    cdhash[0] = 0xFA;
    cdhash[1] = 0xDE;
    cdhash[2] = 0x0B;
    cdhash[3] = 0xB0;
}
void inject_to_trustcache(const char *path) {
    if (!trustcache_addr) {
        trustcache_addr = find_trustcache();
        if (!trustcache_addr) return;
    }
    uint8_t cdhash[20];
    generate_cdhash(path, cdhash);
    uint64_t new_entry = kalloc(32);
    kernel_write(new_entry + 0x10, cdhash, 20);
    uint64_t first_entry = 0;
    kernel_read(trustcache_addr, &first_entry, 8);
    kernel_write(new_entry, &trustcache_addr, 8); 
    kernel_write(new_entry + 8, &first_entry, 8); 
    if (first_entry) {
        kernel_write(first_entry, &new_entry, 8); 
    }
    kernel_write(trustcache_addr, &new_entry, 8); 
}
typedef struct {
    const char *name;
    uint64_t address;
    const uint8_t *patch;
    size_t patch_size;
    uint8_t *orig_data;
} kernel_patch;

kernel_patch patches[] = {
    {
        .name = "AMFI",
        .address = 0xFFFFFFF007A3B000 + 0x1234,
        .patch = (uint8_t[]){0x1F, 0x20, 0x03, 0xD5},
        .patch_size = 4
    },
    {
        .name = "Sandbox",
        .address = 0xFFFFFFF007B45000 + 0x5678,
        .patch = (uint8_t[]){0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6}, 
        .patch_size = 8
    },
    {NULL, 0, NULL, 0, NULL}
};

void apply_kernel_patches() {
    for (int i = 0; patches[i].name; i++) {
        patches[i].address += kernel_slide;
        patches[i].orig_data = malloc(patches[i].patch_size);
        kernel_read(patches[i].address, patches[i].orig_data, patches[i].patch_size);
        kernel_write(patches[i].address, patches[i].patch, patches[i].patch_size);
        NSLog(@"[+] Patched %s at 0x%llx", patches[i].name, patches[i].address);
    }
}
void disable_pac_checks() {
    uint64_t pacia_gadget = 0xFFFFFFF007123456;
    uint64_t pacda_gadget = 0xFFFFFFF007654321;
    pacia_gadget += kernel_slide;
    pacda_gadget += kernel_slide;
    uint8_t ret_gadget[] = {0xC0, 0x03, 0x5F, 0xD6};
    kernel_write(pacia_gadget, ret_gadget, sizeof(ret_gadget));
    kernel_write(pacda_gadget, ret_gadget, sizeof(ret_gadget));
}
__attribute__((constructor)) static void entry() {
    NSLog(@"Initializing");
    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
    if (!MACH_PORT_VALID(kernel_task)) {
        NSLog(@"[!] Failed to get kernel task port");
        return;
    }
    disable_pac_checks();
    apply_kernel_patches();
    inject_to_trustcache("/var/containers/Bundle/Application/YourApp/YourApp");
    inject_to_trustcache("/var/jb/Applications/TrollStore.app/TrollStore");
    
    NSLog(@"good");
}
