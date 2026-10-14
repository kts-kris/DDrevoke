//
// DDRevoke.mm
// DingTalk 9.0.1 (Build 58780930, arm64) Anti-Recall Dynamic Hook Plugin
//
// Target Binary : /Applications/DingTalk.app/Contents/MacOS/DingTalk
// Target Arch   : arm64 (VM_BASE = 0x100000000)
// Target UUID   : 3A164B98-5BBA-3B60-8ADF-7D9DA894025A
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
#include <os/log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <string>
#include <initializer_list>

// ============================================================================
// 1. Target Virtual Addresses (DingTalk 9.0.1 arm64, VM_BASE = 0x100000000)
// ============================================================================
namespace DT901 {
    [[maybe_unused]] static constexpr uintptr_t kVmBase       = 0x100000000ULL;

    // Core C++ recall state mutation & sync handlers
    static constexpr uintptr_t kVA_UpdateRecallStatus         = 0x1019a16f0ULL; // IMMessageCache::UpdateRecallStatus
    static constexpr uintptr_t kVA_RecallMessageByMsgId       = 0x101a7136cULL; // IMMessageServiceImplStd::RecallMessageByMsgId
    static constexpr uintptr_t kVA_InRecallCache              = 0x101ad0808ULL; // SyncRecallCache::InRecallCache
    static constexpr uintptr_t kVA_OnRecallMsgV3Success       = 0x101c206a8ULL; // Outgoing RecallMessageV3 RPC success callback

    // Read-only & extension helper functions inside DingTalk C++ core
    static constexpr uintptr_t kVA_FindMessage                = 0x10199cd78ULL; // IMMessageCache::FindMessage
    static constexpr uintptr_t kVA_SharedPtrMsgDtor           = 0x1000078a8ULL; // std::shared_ptr<DTMessage>::~shared_ptr
    static constexpr uintptr_t kVA_GetGlobalAuthCtx           = 0x1000226f8ULL; // Global C++ Auth/Account Context
    static constexpr uintptr_t kVA_InitCppString              = 0x100004470ULL; // std::string::basic_string(const char*)
    static constexpr uintptr_t kVA_FreeCppStringHeap          = 0x106cfd72cULL; // operator delete(void*)
    static constexpr uintptr_t kVA_GetNameService             = 0x10380cbecULL; // Get global shared_ptr<NameService>
    static constexpr uintptr_t kVA_GetUserDisplayName         = 0x1002e1258ULL; // NameService::GetUserDisplayName
    static constexpr uintptr_t kVA_IMMessage_GetExtension     = 0x101d4b894ULL; // IMMessage::GetExtension (reads +0xb0, locks +0x200)

    // Expected first 4 instructions (16 bytes, little-endian uint32) for safety verification
    static constexpr uint32_t kProlog_UpdateRecallStatus[4]   = {0xa9ba6ffc, 0xa90167fa, 0xa9025ff8, 0xa90357f6};
    static constexpr uint32_t kProlog_RecallMessageByMsgId[4] = {0xa9ba6ffc, 0xa90167fa, 0xa9025ff8, 0xa90357f6};
    static constexpr uint32_t kProlog_InRecallCache[4]        = {0xa9bd57f6, 0xa9014ff4, 0xa9027bfd, 0x910083fd};
    static constexpr uint32_t kProlog_OnRecallMsgV3Success[4] = {0xd10583ff, 0xa91357f6, 0xa9144ff4, 0xa9157bfd};

    // Expected LC_UUID for DingTalk 9.0.1 (58780930) arm64 slice:
    // 3A164B98-5BBA-3B60-8ADF-7D9DA894025A
    static constexpr uint8_t kExpectedUUID[16] = {
        0x3A, 0x16, 0x4B, 0x98, 0x5B, 0xBA, 0x3B, 0x60,
        0x8A, 0xDF, 0x7D, 0x9D, 0xA8, 0x94, 0x02, 0x5A
    };

    // Struct offsets verified from disassembly of IMMessage::~IMMessage (0x101d46e34)
    [[maybe_unused]] static constexpr size_t kOffset_DTMessage_ExtJson      = 0x18;  // libc++ std::string msg_id_str
    [[maybe_unused]] static constexpr size_t kOffset_DTMessage_Mid          = 0x48;  // int64_t
    static constexpr size_t kOffset_DTMessage_SenderUid                     = 0x58;  // int64_t
    static constexpr size_t kOffset_DTMessage_SenderName                    = 0x60;  // libc++ std::string
    [[maybe_unused]] static constexpr size_t kOffset_DTMessage_MsgType      = 0x80;  // int32_t (1=text, 2=image, 3=audio, 4=video, 5=file)
    [[maybe_unused]] static constexpr size_t kOffset_DTMessage_ExtMap       = 0xb0;  // std::map<std::string, std::string>
    [[maybe_unused]] static constexpr size_t kOffset_DTMessage_RecallStatus = 0x160; // int32_t (0 = normal, 1 = recalled)
    [[maybe_unused]] static constexpr size_t kOffset_DTMessage_ShieldStatus = 0x198; // int32_t
    static constexpr size_t kOffset_DTMessage_MutexPtr                     = 0x200; // std::recursive_mutex*
    static constexpr size_t kOffset_DTMessage_Content                      = 0x210; // libc++ std::string (message text body)

    [[maybe_unused]] static constexpr size_t kOffset_ChangeModel_Cid          = 0x08;  // libc++ std::string
    static constexpr size_t kOffset_ChangeModel_Mid                           = 0x28;  // int64_t
    [[maybe_unused]] static constexpr size_t kOffset_ChangeModel_RecallStatus = 0xa4;  // int32_t

    static constexpr size_t kVtable_IMService_GetMsgCache     = 0x688; // vtable slot returning shared_ptr<IMMessageCache>
    static constexpr size_t kVtable_AuthCtx_GetCurrentUid     = 0x1c0; // vtable slot returning int64_t current_uid
}

// ============================================================================
// 2. Logging & libc++ SSO String Helper
// ============================================================================
static os_log_t g_log = nullptr;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void DDLog(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void DDLog(const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (g_log) {
        os_log_with_type(g_log, OS_LOG_TYPE_DEFAULT, "%{public}s", msg);
    }

    pthread_mutex_lock(&g_log_mutex);
    FILE *fp = fopen("/tmp/ddrevoke.log", "a");
    if (fp) {
        time_t now = time(nullptr);
        struct tm tm_now;
        localtime_r(&now, &tm_now);
        char tbuf[32];
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm_now);
        fprintf(fp, "[%s] [DDRevoke] %s\n", tbuf, msg);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_log_mutex);
}

// Safely reads a libc++ std::string (ARM64 alternate/SSO layout used in DingTalk)
// In DingTalk's libc++ ABI (verified at 0x1019d22f0 & 0x1006edc64):
//   byte[23] (+0x17) is signed size/flag: if (int8_t)byte[23] < 0, heap ptr is at +0x00 and size at +0x08;
//   otherwise inline chars start at +0x00 with length = byte[23].
static const char *ReadCppString(const void *str_addr, char *buf, size_t buf_size) {
    if (!str_addr || !buf || buf_size == 0) return "";
    buf[0] = '\0';
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(str_addr);
    int8_t tag = static_cast<int8_t>(bytes[0x17]);
    const char *src = nullptr;
    size_t len = 0;
    if (tag < 0) {
        src = *reinterpret_cast<const char *const *>(bytes);
        len = *reinterpret_cast<const size_t *>(bytes + 0x08);
    } else {
        src = reinterpret_cast<const char *>(bytes);
        len = static_cast<size_t>(tag);
    }
    if (!src || len == 0) return buf;
    if (len >= buf_size) len = buf_size - 1;
    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}

// ============================================================================
// 3. Self-Recalled Message ID Ring Buffer (Tracks Local Outgoing Recalls)
// ============================================================================
static constexpr size_t kSelfRecallRingSize = 128;
static int64_t g_self_recalled_mids[kSelfRecallRingSize] = {0};
static size_t g_self_recalled_idx = 0;
static pthread_mutex_t g_self_mutex = PTHREAD_MUTEX_INITIALIZER;

static void RecordSelfRecalledMid(int64_t mid) {
    if (mid <= 0) return;
    pthread_mutex_lock(&g_self_mutex);
    g_self_recalled_mids[g_self_recalled_idx % kSelfRecallRingSize] = mid;
    g_self_recalled_idx++;
    pthread_mutex_unlock(&g_self_mutex);
    DDLog("[SELF-RECALL-RECORD] Recorded outgoing recall mid=%lld", (long long)mid);
}

static bool IsSelfRecalledMid(int64_t mid) {
    if (mid <= 0) return false;
    bool found = false;
    pthread_mutex_lock(&g_self_mutex);
    for (size_t i = 0; i < kSelfRecallRingSize; ++i) {
        if (g_self_recalled_mids[i] == mid) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_self_mutex);
    return found;
}

// ============================================================================
// 4. Runtime Slide & C++ Bridge Helpers
// ============================================================================
static intptr_t g_slide = 0;

static inline uintptr_t Rebase(uintptr_t static_va) {
    return static_cast<uintptr_t>(static_va + g_slide);
}

struct RawSharedPtr {
    void *ptr;
    void *cntrl;
};

struct alignas(8) RawCppString {
    uint8_t bytes[24];
};

static inline void InitCppString(RawCppString *s, const char *cstr) {
    memset(s, 0, sizeof(*s));
    using InitFn = void *(*)(void *, const char *);
    InitFn fn = reinterpret_cast<InitFn>(Rebase(DT901::kVA_InitCppString));
    fn(s, cstr ? cstr : "");
}

static inline void DestroyCppString(RawCppString *s) {
    if (!s) return;
    int8_t tag = static_cast<int8_t>(s->bytes[0x17]);
    if (tag < 0) {
        void *heap_ptr = *reinterpret_cast<void **>(s->bytes);
        if (heap_ptr) {
            using FreeFn = void (*)(void *);
            FreeFn fn = reinterpret_cast<FreeFn>(Rebase(DT901::kVA_FreeCppStringHeap));
            fn(heap_ptr);
        }
    }
    memset(s, 0, sizeof(*s));
}

// Releases a RawSharedPtr using DingTalk's std::shared_ptr destructor (0x1000078a8)
static inline void ReleaseSharedPtr(RawSharedPtr *sp) {
    if (!sp || !sp->cntrl) return;
    using DtorFn = void *(*)(RawSharedPtr *);
    DtorFn dtor = reinterpret_cast<DtorFn>(Rebase(DT901::kVA_SharedPtrMsgDtor));
    dtor(sp);
    sp->ptr = nullptr;
    sp->cntrl = nullptr;
}

// Calls IMMessageCache::FindMessage(cache, cid, mid) -> writes shared_ptr<DTMessage> via x8 indirect result
static inline void CallFindMessage(void *cache, const void *cid_str, int64_t mid, RawSharedPtr *out_sp) {
    out_sp->ptr = nullptr;
    out_sp->cntrl = nullptr;
    if (!cache || !cid_str || mid <= 0) return;

    uintptr_t fn_addr = Rebase(DT901::kVA_FindMessage);
    register void *x0 __asm__("x0") = cache;
    register const void *x1 __asm__("x1") = cid_str;
    register int64_t x2 __asm__("x2") = mid;
    register RawSharedPtr *x8 __asm__("x8") = out_sp;
    __asm__ volatile(
        "blr %[fn]\n"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x8)
        : [fn] "r"(fn_addr)
        : "x3", "x4", "x5", "x6", "x7", "x9", "x10", "x11", "x12",
          "x13", "x14", "x15", "x16", "x17", "x30",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "memory", "cc"
    );
}

// Calls IMMessageServiceImplStd::GetMessageCache(im_service, cid) via vtable[+0x688] -> writes shared_ptr<IMMessageCache> via x8
static inline void CallGetMessageCache(void *im_service, const void *cid_str, RawSharedPtr *out_cache_sp) {
    out_cache_sp->ptr = nullptr;
    out_cache_sp->cntrl = nullptr;
    if (!im_service || !cid_str) return;

    uintptr_t vtable = *reinterpret_cast<uintptr_t *>(im_service);
    if (!vtable) return;
    uintptr_t fn_addr = *reinterpret_cast<uintptr_t *>(vtable + DT901::kVtable_IMService_GetMsgCache);
    if (!fn_addr) return;

    register void *x0 __asm__("x0") = im_service;
    register const void *x1 __asm__("x1") = cid_str;
    register RawSharedPtr *x8 __asm__("x8") = out_cache_sp;
    __asm__ volatile(
        "blr %[fn]\n"
        : "+r"(x0), "+r"(x1), "+r"(x8)
        : [fn] "r"(fn_addr)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x9", "x10", "x11", "x12",
          "x13", "x14", "x15", "x16", "x17", "x30",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "memory", "cc"
    );
}

// Calls NameService::GetUserDisplayName(name_service, &uid, cid_str, &flag) -> writes std::string via x8
static inline void CallGetUserDisplayName(
    void *name_service,
    int64_t uid,
    const void *cid_str,
    bool use_cid,
    RawCppString *out_str
) {
    memset(out_str, 0, sizeof(*out_str));
    if (!name_service || uid <= 0 || !cid_str) return;

    uintptr_t fn_addr = Rebase(DT901::kVA_GetUserDisplayName);
    int64_t uid_val = uid;
    bool flag_val = use_cid;
    register void *x0 __asm__("x0") = name_service;
    register const int64_t *x1 __asm__("x1") = &uid_val;
    register const void *x2 __asm__("x2") = cid_str;
    register const bool *x3 __asm__("x3") = &flag_val;
    register RawCppString *x8 __asm__("x8") = out_str;
    __asm__ volatile(
        "blr %[fn]\n"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x8)
        : [fn] "r"(fn_addr)
        : "x4", "x5", "x6", "x7", "x9", "x10", "x11", "x12",
          "x13", "x14", "x15", "x16", "x17", "x30",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "memory", "cc"
    );
}

// Calls IMMessage::GetExtension(msg_ptr, key_str) (0x101d4b894: safe read of +0xb0 protected by +0x200 mutex)
static inline void CallIMMessageGetExtension(void *msg_ptr, const RawCppString *key_str, RawCppString *out_str) {
    memset(out_str, 0, sizeof(*out_str));
    if (!msg_ptr || !key_str) return;

    uintptr_t fn_addr = Rebase(DT901::kVA_IMMessage_GetExtension);
    register void *x0 __asm__("x0") = msg_ptr;
    register const RawCppString *x1 __asm__("x1") = key_str;
    register RawCppString *x8 __asm__("x8") = out_str;
    __asm__ volatile(
        "blr %[fn]\n"
        : "+r"(x0), "+r"(x1), "+r"(x8)
        : [fn] "r"(fn_addr)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x9", "x10", "x11", "x12",
          "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x30",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "memory", "cc"
    );
}

// Resolves sender display name using multiple reliable layers:
//   1. IMMessage + 0x60 (sender_name field)
//   2. Objective-C DTUserProfileManager ([mgr findUserProfile:uid])
//   3. NameService::GetUserDisplayName (0x10380cbec -> 0x1002e1258)
//   4. IMMessage extension map (+0xb0) keys "senderName" / "nick" (via safe 0x101d4b894)
//   5. Fallback: formatted "UID:%lld"
static void ResolveSenderName(
    void *msg_ptr,
    const void *cid_str,
    int64_t sender_uid,
    char *out_sender_name,
    size_t name_buf_len
) {
    if (!out_sender_name || name_buf_len == 0) return;
    out_sender_name[0] = '\0';

    // 1. Direct field on IMMessage (+0x60)
    if (msg_ptr) {
        const void *sender_name_str = reinterpret_cast<const void *>(
            reinterpret_cast<uintptr_t>(msg_ptr) + DT901::kOffset_DTMessage_SenderName
        );
        ReadCppString(sender_name_str, out_sender_name, name_buf_len);
        if (out_sender_name[0] != '\0') return;
    }

    // 2. Objective-C DTMojoContactService (official DingTalk 9 contact service)
    if (sender_uid > 0) {
        Class contactCls = objc_getClass("DTMojoContactService");
        if (contactCls) {
            SEL sharedSel = sel_registerName("sharedService");
            if ([contactCls respondsToSelector:sharedSel]) {
                id contactSvc = ((id (*)(id, SEL))objc_msgSend)((id)contactCls, sharedSel);
                if (contactSvc) {
                    SEL aliasSel = sel_registerName("getAliasById:");
                    if ([contactSvc respondsToSelector:aliasSel]) {
                        NSString *alias = ((NSString * (*)(id, SEL, long long))objc_msgSend)(contactSvc, aliasSel, sender_uid);
                        if (alias && [alias length] > 0) {
                            [alias getCString:out_sender_name maxLength:name_buf_len encoding:NSUTF8StringEncoding];
                            if (out_sender_name[0] != '\0') return;
                        }
                    }
                    SEL nickSel = sel_registerName("getNickByUid:");
                    if ([contactSvc respondsToSelector:nickSel]) {
                        NSString *nick = ((NSString * (*)(id, SEL, long long))objc_msgSend)(contactSvc, nickSel, sender_uid);
                        if (nick && [nick length] > 0) {
                            [nick getCString:out_sender_name maxLength:name_buf_len encoding:NSUTF8StringEncoding];
                            if (out_sender_name[0] != '\0') return;
                        }
                    }
                }
            }
        }
    }

    // 3. Global NameService cache (0x10380cbec -> 0x1002e1258)
    if (sender_uid > 0 && cid_str) {
        using GetNameSvcFn = void *(*)();
        GetNameSvcFn get_name_svc = reinterpret_cast<GetNameSvcFn>(Rebase(DT901::kVA_GetNameService));
        void *name_sp_ptr = get_name_svc ? get_name_svc() : nullptr;
        if (name_sp_ptr) {
            void *name_service = *reinterpret_cast<void **>(name_sp_ptr);
            if (name_service) {
                RawCppString display_name;
                CallGetUserDisplayName(name_service, sender_uid, cid_str, true, &display_name);
                ReadCppString(&display_name, out_sender_name, name_buf_len);
                DestroyCppString(&display_name);
                if (out_sender_name[0] != '\0') return;

                CallGetUserDisplayName(name_service, sender_uid, cid_str, false, &display_name);
                ReadCppString(&display_name, out_sender_name, name_buf_len);
                DestroyCppString(&display_name);
                if (out_sender_name[0] != '\0') return;
            }
        }
    }

    // 4. IMMessage extension map (+0xb0) fallback keys (via safe 0x101d4b894)
    if (msg_ptr) {
        static const char *const kExtKeys[] = {"senderName", "nick", "senderNick", "displayName"};
        for (size_t i = 0; i < sizeof(kExtKeys) / sizeof(kExtKeys[0]); ++i) {
            RawCppString key_str;
            RawCppString val_str;
            InitCppString(&key_str, kExtKeys[i]);
            CallIMMessageGetExtension(msg_ptr, &key_str, &val_str);
            ReadCppString(&val_str, out_sender_name, name_buf_len);
            DestroyCppString(&val_str);
            DestroyCppString(&key_str);
            if (out_sender_name[0] != '\0') return;
        }
    }

    // 5. Fallback: format UID cleanly so it is never empty
    if (sender_uid > 0) {
        snprintf(out_sender_name, name_buf_len, "UID:%lld", (long long)sender_uid);
    }
}

// Queries the current logged-in user's UID (int64_t)
// Primary: C++ AuthContext (0x1000226f8 -> vtable[+0x1c0], verified at 0x101d47100)
// Fallback: Objective-C [[[DTMojoAuthService sharedService] lastUser] uid]
static int64_t GetCurrentUserId() {
    // 1. C++ Global Auth Context
    using GetAuthCtxFn = void *(*)();
    GetAuthCtxFn get_ctx = reinterpret_cast<GetAuthCtxFn>(Rebase(DT901::kVA_GetGlobalAuthCtx));
    if (get_ctx) {
        void *ctx = get_ctx();
        if (ctx) {
            uintptr_t vtable = *reinterpret_cast<uintptr_t *>(ctx);
            if (vtable) {
                using GetUidFn = int64_t (*)(void *);
                GetUidFn get_uid = *reinterpret_cast<GetUidFn *>(vtable + DT901::kVtable_AuthCtx_GetCurrentUid);
                if (get_uid) {
                    int64_t uid = get_uid(ctx);
                    if (uid > 0) return uid;
                }
            }
        }
    }

    // 2. Objective-C Fallback
    Class authCls = objc_getClass("DTMojoAuthService");
    if (authCls) {
        SEL sharedSel = sel_registerName("sharedService");
        SEL lastUserSel = sel_registerName("lastUser");
        SEL uidSel = sel_registerName("uid");
        id service = ((id (*)(id, SEL))objc_msgSend)((id)authCls, sharedSel);
        if (service) {
            id lastUser = ((id (*)(id, SEL))objc_msgSend)(service, lastUserSel);
            if (lastUser) {
                int64_t uid = ((int64_t (*)(id, SEL))objc_msgSend)(lastUser, uidSel);
                if (uid > 0) return uid;
            }
        }
    }
    return -1;
}

// Inspects a cached/DB DTMessage* and determines whether it was sent by the current logged-in user
static bool IsMessageFromSelf(
    void *msg_ptr,
    const void *cid_str,
    int64_t mid,
    int64_t *out_sender_uid,
    char *out_sender_name,
    size_t name_buf_len
) {
    if (out_sender_uid) *out_sender_uid = -1;
    if (out_sender_name && name_buf_len > 0) out_sender_name[0] = '\0';

    if (IsSelfRecalledMid(mid)) {
        return true;
    }
    if (!msg_ptr) {
        return false;
    }

    int64_t sender_uid = *reinterpret_cast<const int64_t *>(
        reinterpret_cast<uintptr_t>(msg_ptr) + DT901::kOffset_DTMessage_SenderUid
    );
    if (out_sender_uid) *out_sender_uid = sender_uid;

    ResolveSenderName(msg_ptr, cid_str, sender_uid, out_sender_name, name_buf_len);

    int64_t current_uid = GetCurrentUserId();
    if (sender_uid > 0 && current_uid > 0 && sender_uid == current_uid) {
        return true;
    }
    return false;
}

// ============================================================================
// 5. Minimal Self-Contained ARM64 Inline Hook Engine (16-Byte Jump Patch)
// ============================================================================
// Uses a 16-byte absolute branch sequence:
//   0x00: 0x58000050   ldr x16, #8
//   0x04: 0xd61f0200   br  x16
//   0x08: .quad <64-bit target address>
// Notice: All hooked functions have 4 pure stack/register instructions in their
// first 16 bytes (verified against kProlog_*), requiring no PC-relative fixups.

static bool InstallInlineHook64(
    const char *name,
    uintptr_t target_va,
    const uint32_t expected_prolog[4],
    void *replacement_fn,
    void **out_trampoline
) {
    uint32_t *target_insns = reinterpret_cast<uint32_t *>(target_va);
    for (int i = 0; i < 4; ++i) {
        if (target_insns[i] != expected_prolog[i]) {
            DDLog("[HOOK-ABORT] %s @ 0x%lx prolog mismatch at insn[%d]: got 0x%08x, expected 0x%08x",
                  name, (unsigned long)target_va, i, target_insns[i], expected_prolog[i]);
            return false;
        }
    }

    // 1. Allocate executable trampoline page (32 bytes used: 16B original prolog + 16B jump back)
    void *tramp = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (tramp == MAP_FAILED) {
        DDLog("[HOOK-ERROR] %s mmap trampoline failed", name);
        return false;
    }

    uint32_t *tramp_u32 = reinterpret_cast<uint32_t *>(tramp);
    memcpy(tramp_u32, target_insns, 16);
    tramp_u32[4] = 0x58000050; // ldr x16, #8
    tramp_u32[5] = 0xd61f0200; // br  x16
    *reinterpret_cast<uint64_t *>(&tramp_u32[6]) = static_cast<uint64_t>(target_va + 16);

    if (mprotect(tramp, PAGE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        DDLog("[HOOK-ERROR] %s mprotect trampoline RX failed", name);
        munmap(tramp, PAGE_SIZE);
        return false;
    }
    sys_icache_invalidate(tramp, 32);

    // 2. Unprotect target __TEXT page(s) using VM_PROT_COPY for COW text patching
    uintptr_t page_start = target_va & ~(static_cast<uintptr_t>(PAGE_SIZE - 1));
    uintptr_t page_end   = (target_va + 16 + PAGE_SIZE - 1) & ~(static_cast<uintptr_t>(PAGE_SIZE - 1));
    mach_vm_size_t patch_len = page_end - page_start;

    kern_return_t kr = mach_vm_protect(
        mach_task_self(),
        static_cast<mach_vm_address_t>(page_start),
        patch_len,
        FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
    );
    if (kr != KERN_SUCCESS) {
        DDLog("[HOOK-ERROR] %s mach_vm_protect RW+COPY failed: kr=%d", name, kr);
        munmap(tramp, PAGE_SIZE);
        return false;
    }

    // 3. Write 16-byte jump to replacement_fn
    target_insns[0] = 0x58000050; // ldr x16, #8
    target_insns[1] = 0xd61f0200; // br  x16
    *reinterpret_cast<uint64_t *>(&target_insns[2]) = reinterpret_cast<uint64_t>(replacement_fn);

    // 4. Restore RX protection & flush instruction cache
    kr = mach_vm_protect(
        mach_task_self(),
        static_cast<mach_vm_address_t>(page_start),
        patch_len,
        FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE
    );
    sys_icache_invalidate(reinterpret_cast<void *>(target_va), 16);

    *out_trampoline = tramp;
    DDLog("[HOOK-OK] Installed %s @ 0x%lx -> replacement %p (trampoline %p)",
          name, (unsigned long)target_va, replacement_fn, tramp);
    return true;
}

// ============================================================================
// 6. Hook Implementations
// ============================================================================

// --- Hook A: Outgoing RecallMessageV3 RPC Success Callback (0x101c206a8) ---
using OnRecallMsgV3SuccessFn = void (*)(void *closure, const void *result_vec);
static OnRecallMsgV3SuccessFn g_orig_OnRecallMsgV3Success = nullptr;

static void Hook_OnRecallMsgV3Success(void *closure, const void *result_vec) {
    if (closure) {
        // [closure + 0x40] is std::vector<int64_t> request_mids (verified at 0x101c20734)
        const int64_t *begin = *reinterpret_cast<const int64_t *const *>(
            reinterpret_cast<uintptr_t>(closure) + 0x40
        );
        const int64_t *end = *reinterpret_cast<const int64_t *const *>(
            reinterpret_cast<uintptr_t>(closure) + 0x48
        );
        if (begin && end && end >= begin && (end - begin) <= 64) {
            for (const int64_t *p = begin; p < end; ++p) {
                RecordSelfRecalledMid(*p);
            }
        }
    }
    g_orig_OnRecallMsgV3Success(closure, result_vec);
}

// --- Hook B & C Shared Helper: Mark Message as Recalled ([已撤回] Tail Badge) ---
using UpdateRecallStatusFn = bool (*)(
    void *cache,
    const void *cid_str,
    const int64_t *mid_ptr,
    const int32_t *recall_status_ptr,
    const int32_t *shield_status_ptr,
    const void *extension_map,
    void *on_success_cb,
    void *on_error_cb
);
static UpdateRecallStatusFn g_orig_UpdateRecallStatus = nullptr;

static void MarkRecalledMessage(void *msg_ptr, int64_t mid) {
    if (!msg_ptr || mid <= 0) return;

    void *content_str = reinterpret_cast<void *>(
        reinterpret_cast<uintptr_t>(msg_ptr) + DT901::kOffset_DTMessage_Content
    );
    char buf[4096] = {0};
    ReadCppString(content_str, buf, sizeof(buf));

    if (strncmp(buf, "[已撤回]", strlen("[已撤回]")) == 0) {
        return; // Already tagged
    }

    char new_buf[4200];
    if (buf[0] != '\0') {
        snprintf(new_buf, sizeof(new_buf), "[已撤回] %s", buf);
    } else {
        snprintf(new_buf, sizeof(new_buf), "[已撤回]");
    }

    void *mutex_ptr = *reinterpret_cast<void **>(
        reinterpret_cast<uintptr_t>(msg_ptr) + DT901::kOffset_DTMessage_MutexPtr
    );
    if (mutex_ptr) {
        pthread_mutex_lock(reinterpret_cast<pthread_mutex_t *>(mutex_ptr));
    }

    DestroyCppString(reinterpret_cast<RawCppString *>(content_str));
    InitCppString(reinterpret_cast<RawCppString *>(content_str), new_buf);

    if (mutex_ptr) {
        pthread_mutex_unlock(reinterpret_cast<pthread_mutex_t *>(mutex_ptr));
    }

    DDLog("[MARK-RECALLED] Tagged message mid=%lld with [已撤回]: \"%s\"", (long long)mid, new_buf);
}

// ============================================================================
// Configuration & Preferences Persistence (~/Library/Application Support/DDRevoke)
// ============================================================================
struct DDRevokeConfig {
    bool enabled = true;
    bool attach_emotion = true;
    std::string emotion_name = "[思考]"; // Default: 🤔 思考
    bool play_sound = true;
    bool show_notification = true;
    std::string update_url = "https://raw.githubusercontent.com/kts-kris/DDrevoke/main/version.json";
    bool auto_check_update = true;
};

static DDRevokeConfig g_config;
static pthread_mutex_t g_config_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_intercepted_count = 0;

static NSString *GetConfigFilePath() {
    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [appSupport stringByAppendingPathComponent:@"DDRevoke"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return [dir stringByAppendingPathComponent:@"config.json"];
}

static void LoadConfig() {
    pthread_mutex_lock(&g_config_mutex);
    NSString *path = GetConfigFilePath();
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (data) {
        NSError *err = nil;
        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
        if ([dict isKindOfClass:[NSDictionary class]]) {
            if (dict[@"enabled"]) g_config.enabled = [dict[@"enabled"] boolValue];
            if (dict[@"attach_emotion"]) g_config.attach_emotion = [dict[@"attach_emotion"] boolValue];
            if (dict[@"emotion_name"] && [dict[@"emotion_name"] isKindOfClass:[NSString class]]) {
                NSString *rawEmotion = dict[@"emotion_name"];
                if ([rawEmotion hasPrefix:@"emotion_"]) {
                    if ([rawEmotion isEqualToString:@"emotion_019"]) g_config.emotion_name = "[嘘]";
                    else if ([rawEmotion isEqualToString:@"emotion_033"]) g_config.emotion_name = "[吃瓜]";
                    else if ([rawEmotion isEqualToString:@"emotion_041"]) g_config.emotion_name = "[捂脸哭]";
                    else if ([rawEmotion isEqualToString:@"emotion_001"]) g_config.emotion_name = "[赞]";
                    else if ([rawEmotion isEqualToString:@"emotion_021"]) g_config.emotion_name = "[OK]";
                    else if ([rawEmotion isEqualToString:@"emotion_003"]) g_config.emotion_name = "[鼓掌]";
                    else if ([rawEmotion isEqualToString:@"emotion_006"]) g_config.emotion_name = "[笑哭]";
                    else if ([rawEmotion isEqualToString:@"emotion_012"]) g_config.emotion_name = "[大哭]";
                    else g_config.emotion_name = "[思考]";
                    DDLog("[CONFIG] Migrated legacy emotion_name '%s' to '%s'",
                          [rawEmotion UTF8String], g_config.emotion_name.c_str());
                } else {
                    g_config.emotion_name = [rawEmotion UTF8String];
                }
            }
            if (dict[@"play_sound"]) g_config.play_sound = [dict[@"play_sound"] boolValue];
            if (dict[@"show_notification"]) g_config.show_notification = [dict[@"show_notification"] boolValue];
            if (dict[@"update_url"] && [dict[@"update_url"] isKindOfClass:[NSString class]]) {
                g_config.update_url = [dict[@"update_url"] UTF8String];
            }
            if (dict[@"auto_check_update"]) {
                g_config.auto_check_update = [dict[@"auto_check_update"] boolValue];
            }
            DDLog("[CONFIG] Loaded config from %s: enabled=%d, attach_emotion=%d, emotion=%s, sound=%d, notif=%d, update_url=%s",
                  [path UTF8String], g_config.enabled, g_config.attach_emotion,
                  g_config.emotion_name.c_str(), g_config.play_sound, g_config.show_notification,
                  g_config.update_url.c_str());
        }
    } else {
        DDLog("[CONFIG] Config not found, initialized with default settings");
    }
    pthread_mutex_unlock(&g_config_mutex);
}

static void SaveConfig() {
    pthread_mutex_lock(&g_config_mutex);
    NSString *path = GetConfigFilePath();
    NSDictionary *dict = @{
        @"enabled": @(g_config.enabled),
        @"attach_emotion": @(g_config.attach_emotion),
        @"emotion_name": [NSString stringWithUTF8String:g_config.emotion_name.c_str()],
        @"play_sound": @(g_config.play_sound),
        @"show_notification": @(g_config.show_notification),
        @"update_url": [NSString stringWithUTF8String:g_config.update_url.c_str()],
        @"auto_check_update": @(g_config.auto_check_update)
    };
    NSError *err = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:&err];
    if (data) {
        [data writeToFile:path atomically:YES];
        DDLog("[CONFIG] Saved config to %s", [path UTF8String]);
    }
    pthread_mutex_unlock(&g_config_mutex);
}

// ============================================================================
// Notification Dispatcher (macOS System Banner & Audio Cue)
// ============================================================================
static int64_t g_last_notified_mid = 0;
static time_t g_last_notified_time = 0;
static pthread_mutex_t g_notif_mutex = PTHREAD_MUTEX_INITIALIZER;

static void NotifyUserRecalled(const char *sender_name, int64_t sender_uid, int64_t mid) {
    if (mid <= 0) return;

    pthread_mutex_lock(&g_notif_mutex);
    time_t now = time(nullptr);
    if (mid == g_last_notified_mid && (now - g_last_notified_time) < 4) {
        pthread_mutex_unlock(&g_notif_mutex);
        return; // Deduplicate rapid callbacks for the same mid
    }
    g_last_notified_mid = mid;
    g_last_notified_time = now;
    pthread_mutex_unlock(&g_notif_mutex);

    pthread_mutex_lock(&g_config_mutex);
    bool play_sound = g_config.play_sound;
    bool show_notif = g_config.show_notification;
    pthread_mutex_unlock(&g_config_mutex);

    NSString *nameStr = (sender_name && sender_name[0] != '\0')
        ? [NSString stringWithUTF8String:sender_name]
        : (sender_uid > 0 ? [NSString stringWithFormat:@"UID:%lld", (long long)sender_uid] : @"对方");

    dispatch_async(dispatch_get_main_queue(), ^{
        // 1. Play alert sound if enabled
        if (play_sound) {
            NSBeep();
        }

        // 2. Deliver system notification if enabled
        if (!show_notif) return;

        Class unCenterCls = objc_getClass("UNUserNotificationCenter");
        Class unContentCls = objc_getClass("UNMutableNotificationContent");
        Class unReqCls = objc_getClass("UNNotificationRequest");
        Class unSoundCls = objc_getClass("UNNotificationSound");

        if (unCenterCls && unContentCls && unReqCls) {
            id center = ((id (*)(id, SEL))objc_msgSend)((id)unCenterCls, sel_registerName("currentNotificationCenter"));
            id content = [[unContentCls alloc] init];
            ((void (*)(id, SEL, id))objc_msgSend)(content, sel_registerName("setTitle:"), @"【钉钉防撤回】拦截到撤回消息");
            NSString *body = [NSString stringWithFormat:@"%@ 尝试撤回消息，DDRevoke 已保留原消息。", nameStr];
            ((void (*)(id, SEL, id))objc_msgSend)(content, sel_registerName("setBody:"), body);
            if (unSoundCls && play_sound) {
                id sound = ((id (*)(id, SEL))objc_msgSend)((id)unSoundCls, sel_registerName("defaultSound"));
                ((void (*)(id, SEL, id))objc_msgSend)(content, sel_registerName("setSound:"), sound);
            }
            NSString *reqId = [NSString stringWithFormat:@"ddrevoke-%lld-%ld", (long long)mid, (long)time(nullptr)];
            id req = ((id (*)(id, SEL, id, id, id))objc_msgSend)(
                (id)unReqCls, sel_registerName("requestWithIdentifier:content:trigger:"), reqId, content, nil
            );
            ((void (*)(id, SEL, id, id))objc_msgSend)(
                center, sel_registerName("addNotificationRequest:withCompletionHandler:"), req, nil
            );
        }

        // Deliver via NSUserNotificationCenter as fallback
        Class nsCenterCls = objc_getClass("NSUserNotificationCenter");
        Class nsNotifCls = objc_getClass("NSUserNotification");
        if (nsCenterCls && nsNotifCls) {
            id center = ((id (*)(id, SEL))objc_msgSend)((id)nsCenterCls, sel_registerName("defaultUserNotificationCenter"));
            id notif = [[nsNotifCls alloc] init];
            ((void (*)(id, SEL, id))objc_msgSend)(notif, sel_registerName("setTitle:"), @"【钉钉防撤回】拦截到撤回消息");
            ((void (*)(id, SEL, id))objc_msgSend)(notif, sel_registerName("setSubtitle:"), [NSString stringWithFormat:@"发送人: %@", nameStr]);
            ((void (*)(id, SEL, id))objc_msgSend)(notif, sel_registerName("setInformativeText:"), @"对方已撤回该消息，DDRevoke 已为您保留原消息。");
            if (play_sound) {
                ((void (*)(id, SEL, id))objc_msgSend)(notif, sel_registerName("setSoundName:"), @"NSUserNotificationDefaultSoundName");
            }
            ((void (*)(id, SEL, id))objc_msgSend)(center, sel_registerName("deliverNotification:"), notif);
        }
    });

    DDLog("[NOTIFY-USER] Delivered notification banner & sound for recall mid=%lld from \"%s\"",
          (long long)mid, [nameStr UTF8String]);
}

// ============================================================================
// Recalled Message Emotion Reaction Badge ("贴表情" 标记)
// ============================================================================
static constexpr size_t kEmotionDedupSize = 64;
static int64_t g_emotion_dedup_mids[kEmotionDedupSize] = {0};
static time_t g_emotion_dedup_times[kEmotionDedupSize] = {0};
static size_t g_emotion_dedup_idx = 0;
static pthread_mutex_t g_emotion_mutex = PTHREAD_MUTEX_INITIALIZER;

static void AttachEmotionToRecalledMessage(const char *cid, int64_t sender_uid, int64_t mid) {
    if (!cid || cid[0] == '\0' || mid <= 0 || sender_uid <= 0) return;

    pthread_mutex_lock(&g_config_mutex);
    bool should_attach = g_config.attach_emotion;
    std::string emotion_name = g_config.emotion_name;
    pthread_mutex_unlock(&g_config_mutex);

    if (!should_attach) {
        DDLog("[EMOTION] Auto-attach emotion is disabled in settings, skipping mid=%lld", (long long)mid);
        return;
    }

    // Deduplicate rapid dual-stream (SYNC + PUSH) recalls for same message
    pthread_mutex_lock(&g_emotion_mutex);
    time_t now = time(nullptr);
    for (size_t i = 0; i < kEmotionDedupSize; ++i) {
        if (g_emotion_dedup_mids[i] == mid && (now - g_emotion_dedup_times[i]) < 10) {
            pthread_mutex_unlock(&g_emotion_mutex);
            return;
        }
    }
    g_emotion_dedup_mids[g_emotion_dedup_idx % kEmotionDedupSize] = mid;
    g_emotion_dedup_times[g_emotion_dedup_idx % kEmotionDedupSize] = now;
    g_emotion_dedup_idx++;
    pthread_mutex_unlock(&g_emotion_mutex);

    // Create immutable NSString copies before dispatching
    NSString *cidStr = [NSString stringWithUTF8String:cid];
    NSString *emotionNameStr = [NSString stringWithUTF8String:emotion_name.c_str()];
    if (!cidStr || !emotionNameStr || [emotionNameStr length] == 0) return;

    // Normalize emotion to DingTalk standard bracketed key [xxx]
    if ([emotionNameStr hasPrefix:@"emotion_"]) {
        emotionNameStr = @"[思考]";
    } else if (![emotionNameStr hasPrefix:@"["] || ![emotionNameStr hasSuffix:@"]"]) {
        Class utilCls = objc_getClass("DTIMConvTopicUtil");
        SEL keySel = sel_registerName("keyForEmotionName:");
        if (utilCls && [utilCls respondsToSelector:keySel]) {
            emotionNameStr = ((id (*)(id, SEL, id))objc_msgSend)((id)utilCls, keySel, emotionNameStr);
        } else {
            emotionNameStr = [NSString stringWithFormat:@"[%@]", emotionNameStr];
        }
    }

    // Delay 150ms to allow DingTalk's SQLite DB and in-memory cache commit to settle
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(150 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
        Class mojoCls = objc_getClass("DTMojoMessageService");
        if (!mojoCls) return;
        SEL sharedSel = sel_registerName("sharedService");
        if (![mojoCls respondsToSelector:sharedSel]) return;
        id svc = ((id (*)(id, SEL))objc_msgSend)((id)mojoCls, sharedSel);
        if (!svc) return;

        SEL replySel = sel_registerName("replyEmotionWithCid:emotionName:originSenderId:originMsgId:completionHandler:");
        if (![svc respondsToSelector:replySel]) return;

        // DingTalk requires non-nil completionHandler (0x100607670 has cbz x20, which early-returns on nil).
        // The callback block receives 1 argument (error object or nil on success).
        void (^completionHandler)(id) = ^(id error) {
            if (error) {
                DDLog("[EMOTION] replyEmotion callback for mid=%lld failed: %s",
                      (long long)mid, [[error description] UTF8String]);
            } else {
                DDLog("[EMOTION] replyEmotion callback for mid=%lld completed successfully!", (long long)mid);
            }
        };

        ((void (*)(id, SEL, id, id, long long, long long, id))objc_msgSend)(
            svc, replySel, cidStr, emotionNameStr, sender_uid, mid, completionHandler
        );
        DDLog("[EMOTION] Dispatched auto-reaction (%s) for mid=%lld in cid=%s (sender_uid=%lld)",
              [emotionNameStr UTF8String], (long long)mid, [cidStr UTF8String], (long long)sender_uid);
    });
}

// --- Hook B: [SYNC] Single-Message Recall Processor (0x101a7136c) ---
// Covers the [SYNC] stream path (0x101ac958c -> 0x101a7136c) before conversation
// preview update (0x101a7167c) or cache/DB recall status update (0x101a71bc0).
using RecallMessageByMsgIdFn = void (*)(void *im_service, const void *cid_str, const void *change_model);
static RecallMessageByMsgIdFn g_orig_RecallMessageByMsgId = nullptr;

static void Hook_RecallMessageByMsgId(void *im_service, const void *cid_str, const void *change_model) {
    if (!im_service || !cid_str || !change_model) {
        g_orig_RecallMessageByMsgId(im_service, cid_str, change_model);
        return;
    }

    pthread_mutex_lock(&g_config_mutex);
    bool is_enabled = g_config.enabled;
    pthread_mutex_unlock(&g_config_mutex);

    if (!is_enabled) {
        g_orig_RecallMessageByMsgId(im_service, cid_str, change_model);
        return;
    }

    int64_t mid = *reinterpret_cast<const int64_t *>(
        reinterpret_cast<uintptr_t>(change_model) + DT901::kOffset_ChangeModel_Mid
    );
    char cid_buf[128];
    ReadCppString(cid_str, cid_buf, sizeof(cid_buf));

    // Look up message in IMMessageCache/DB to inspect sender_uid (+0x58)
    RawSharedPtr cache_sp = {nullptr, nullptr};
    RawSharedPtr msg_sp   = {nullptr, nullptr};
    CallGetMessageCache(im_service, cid_str, &cache_sp);
    if (cache_sp.ptr) {
        CallFindMessage(cache_sp.ptr, cid_str, mid, &msg_sp);
    }

    int64_t sender_uid = -1;
    char sender_name[128] = {0};
    bool is_self = IsMessageFromSelf(msg_sp.ptr, cid_str, mid, &sender_uid, sender_name, sizeof(sender_name));

    if (is_self) {
        ReleaseSharedPtr(&msg_sp);
        ReleaseSharedPtr(&cache_sp);
        DDLog("[ALLOW-SELF] [SYNC] Allowing self-recalled message: cid=%s, mid=%lld, sender_uid=%lld",
              cid_buf, (long long)mid, (long long)sender_uid);
        g_orig_RecallMessageByMsgId(im_service, cid_str, change_model);
        return;
    }

    if (msg_sp.ptr) {
        MarkRecalledMessage(msg_sp.ptr, mid);
    }
    ReleaseSharedPtr(&msg_sp);
    ReleaseSharedPtr(&cache_sp);

    g_intercepted_count++;
    NotifyUserRecalled(sender_name, sender_uid, mid);
    AttachEmotionToRecalledMessage(cid_buf, sender_uid, mid);

    DDLog("[INTERCEPT-OTHER] [SYNC] Blocked recall from other user & marked [已撤回]: cid=%s, mid=%lld, sender_uid=%lld, sender_name=\"%s\" (current_uid=%lld, total_intercepted=%u)",
          cid_buf, (long long)mid, (long long)sender_uid, sender_name, (long long)GetCurrentUserId(), g_intercepted_count);
    // Return without calling original: keeps conversation preview, SQLite DB, and chat bubble intact with [已撤回] badge.
}

// --- Hook C: IMMessageCache::UpdateRecallStatus (0x1019a16f0) ---
// Unified bottleneck covering both [PUSH] notice path (0x1019d2548) and [SYNC] path (0x101a71bc0).
static bool Hook_UpdateRecallStatus(
    void *cache,
    const void *cid_str,
    const int64_t *mid_ptr,
    const int32_t *recall_status_ptr,
    const int32_t *shield_status_ptr,
    const void *extension_map,
    void *on_success_cb,
    void *on_error_cb
) {
    int64_t mid = mid_ptr ? *mid_ptr : -1;
    int32_t recall_status = recall_status_ptr ? *recall_status_ptr : 0;

    pthread_mutex_lock(&g_config_mutex);
    bool is_enabled = g_config.enabled;
    pthread_mutex_unlock(&g_config_mutex);

    if (is_enabled && recall_status == 1 && cache && cid_str && mid > 0) {
        char cid_buf[128];
        ReadCppString(cid_str, cid_buf, sizeof(cid_buf));

        RawSharedPtr msg_sp = {nullptr, nullptr};
        CallFindMessage(cache, cid_str, mid, &msg_sp);

        int64_t sender_uid = -1;
        char sender_name[128] = {0};
        bool is_self = IsMessageFromSelf(msg_sp.ptr, cid_str, mid, &sender_uid, sender_name, sizeof(sender_name));

        if (!is_self) {
            if (msg_sp.ptr) {
                MarkRecalledMessage(msg_sp.ptr, mid);
            }
            ReleaseSharedPtr(&msg_sp);
            g_intercepted_count++;
            NotifyUserRecalled(sender_name, sender_uid, mid);
            AttachEmotionToRecalledMessage(cid_buf, sender_uid, mid);
            DDLog("[INTERCEPT-OTHER] [CACHE/PUSH] Blocked UpdateRecallStatus & marked [已撤回]: cid=%s, mid=%lld, sender_uid=%lld, sender_name=\"%s\" (current_uid=%lld, total_intercepted=%u)",
                  cid_buf, (long long)mid, (long long)sender_uid, sender_name, (long long)GetCurrentUserId(), g_intercepted_count);
            return true;
        }

        ReleaseSharedPtr(&msg_sp);
        DDLog("[ALLOW-SELF] [CACHE/PUSH] Allowing UpdateRecallStatus for self-recall: cid=%s, mid=%lld, sender_uid=%lld",
              cid_buf, (long long)mid, (long long)sender_uid);
    }

    return g_orig_UpdateRecallStatus(
        cache, cid_str, mid_ptr, recall_status_ptr, shield_status_ptr,
        extension_map, on_success_cb, on_error_cb
    );
}

// --- Hook D: SyncRecallCache::InRecallCache (0x101ad0808) ---
// Prevents out-of-order messages from being dropped if their recall packet arrived first.
using InRecallCacheFn = bool (*)(void *recall_cache, int64_t mid);
static InRecallCacheFn g_orig_InRecallCache = nullptr;

static bool Hook_InRecallCache(void *recall_cache, int64_t mid) {
    bool in_cache = g_orig_InRecallCache(recall_cache, mid);
    if (in_cache && !IsSelfRecalledMid(mid)) {
        DDLog("[INTERCEPT-OTHER] [OUT-OF-ORDER] Bypassed InRecallCache drop for mid=%lld", (long long)mid);
        return false;
    }
    return in_cache;
}

// --- Hook E: Objective-C Outgoing Recall Swizzles (DTMojoMessageService) ---
static IMP g_orig_objc_recallMessage = nullptr;
static IMP g_orig_objc_recallYunpanMsg = nullptr;

static void Swizzled_recallMessage(id self, SEL _cmd, NSString *cid, int64_t mid, id completion) {
    RecordSelfRecalledMid(mid);
    if (g_orig_objc_recallMessage) {
        ((void (*)(id, SEL, NSString *, int64_t, id))g_orig_objc_recallMessage)(self, _cmd, cid, mid, completion);
    }
}

static void Swizzled_recallYunpanMsg(id self, SEL _cmd, NSString *cid, int64_t mid, id completion) {
    RecordSelfRecalledMid(mid);
    if (g_orig_objc_recallYunpanMsg) {
        ((void (*)(id, SEL, NSString *, int64_t, id))g_orig_objc_recallYunpanMsg)(self, _cmd, cid, mid, completion);
    }
}

static void InstallObjCSwizzles() {
    Class cls = objc_getClass("DTMojoMessageService");
    if (!cls) {
        DDLog("[WARN] Objective-C class DTMojoMessageService not found");
        return;
    }
    Method m1 = class_getInstanceMethod(cls, sel_registerName("recallMessage:mid:completionHandler:"));
    if (m1) {
        g_orig_objc_recallMessage = method_setImplementation(m1, (IMP)Swizzled_recallMessage);
        DDLog("[HOOK-OK] Swizzled -[DTMojoMessageService recallMessage:mid:completionHandler:]");
    }
    Method m2 = class_getInstanceMethod(cls, sel_registerName("recallYunpanMsg:mid:completionHandler:"));
    if (m2) {
        g_orig_objc_recallYunpanMsg = method_setImplementation(m2, (IMP)Swizzled_recallYunpanMsg);
        DDLog("[HOOK-OK] Swizzled -[DTMojoMessageService recallYunpanMsg:mid:completionHandler:]");
    }
}

// ============================================================================
// 7. AppKit Native Settings Window & Menu Bar Injection
// ============================================================================

struct DDRevokeEmotionOption {
    const char *name;
    const char *code;
};

static const DDRevokeEmotionOption kEmotionOptions[] = {
    {"🤔 思考 (推荐)", "[思考]"},
    {"👍 点赞 (认同)", "[赞]"},
    {"👌 收到 (OK)", "[OK]"},
    {"👏 鼓掌 (恭喜)", "[鼓掌]"},
    {"🤫 嘘 (保持低调)", "[嘘]"},
    {"🍉 吃瓜 (围观)", "[吃瓜]"},
    {"🤦 捂脸 (无奈)", "[捂脸哭]"},
    {"😂 笑哭 (喜极而泣)", "[笑哭]"},
    {"😭 大哭 (伤心)", "[大哭]"}
};

@interface DDRevokeUpdateManager : NSObject
+ (instancetype)sharedManager;
- (void)checkForUpdates:(BOOL)manualCheck;
@end

@interface DDRevokeSettingsWindowController : NSWindowController <NSWindowDelegate>
+ (instancetype)sharedController;
- (void)showSettingsWindow;
- (void)checkUpdate:(id)sender;
@end

@implementation DDRevokeSettingsWindowController {
    NSButton *_enabledCheck;
    NSButton *_emotionCheck;
    NSPopUpButton *_emotionPopup;
    NSButton *_soundCheck;
    NSButton *_notifCheck;
    NSTextField *_statusLabel;
}

+ (instancetype)sharedController {
    static DDRevokeSettingsWindowController *s_instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_instance = [[DDRevokeSettingsWindowController alloc] init];
    });
    return s_instance;
}

- (instancetype)init {
    NSRect frame = NSMakeRect(0, 0, 440, 360);
    NSWindow *win = [[NSWindow alloc] initWithContentRect:frame
                                                styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                                  backing:NSBackingStoreBuffered
                                                    defer:NO];
    [win setTitle:@"DDRevoke 防撤回设置"];
    [win setReleasedWhenClosed:NO];
    [win center];
    [win setLevel:NSFloatingWindowLevel];
    self = [super initWithWindow:win];
    if (self) {
        [self setupUI];
    }
    return self;
}

- (void)setupUI {
    NSView *contentView = self.window.contentView;

    // 1. Header Title
    NSTextField *titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(24, 315, 390, 26)];
    [titleLabel setStringValue:@"🛡️ 钉钉防撤回补丁 (DDRevoke v1.0.3)"];
    [titleLabel setFont:[NSFont boldSystemFontOfSize:15]];
    [titleLabel setBezeled:NO];
    [titleLabel setDrawsBackground:NO];
    [titleLabel setEditable:NO];
    [titleLabel setSelectable:NO];
    [contentView addSubview:titleLabel];

    // Status / Statistics Label
    _statusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(24, 292, 390, 18)];
    [_statusLabel setFont:[NSFont systemFontOfSize:11]];
    [_statusLabel setTextColor:[NSColor secondaryLabelColor]];
    [_statusLabel setBezeled:NO];
    [_statusLabel setDrawsBackground:NO];
    [_statusLabel setEditable:NO];
    [_statusLabel setSelectable:NO];
    [contentView addSubview:_statusLabel];

    // Top Separator
    NSBox *sep1 = [[NSBox alloc] initWithFrame:NSMakeRect(24, 280, 392, 1)];
    [sep1 setBoxType:NSBoxSeparator];
    [contentView addSubview:sep1];

    // 2. Master Switch
    _enabledCheck = [[NSButton alloc] initWithFrame:NSMakeRect(24, 245, 390, 22)];
    [_enabledCheck setButtonType:NSButtonTypeSwitch];
    [_enabledCheck setTitle:@"启用消息防撤回 (保留被撤回的消息)"];
    [_enabledCheck setFont:[NSFont systemFontOfSize:13]];
    [_enabledCheck setTarget:self];
    [_enabledCheck setAction:@selector(controlChanged:)];
    [contentView addSubview:_enabledCheck];

    // 3. Attach Emotion Reaction
    _emotionCheck = [[NSButton alloc] initWithFrame:NSMakeRect(24, 215, 390, 22)];
    [_emotionCheck setButtonType:NSButtonTypeSwitch];
    [_emotionCheck setTitle:@"撤回消息下方自动贴表情标记"];
    [_emotionCheck setFont:[NSFont systemFontOfSize:13]];
    [_emotionCheck setTarget:self];
    [_emotionCheck setAction:@selector(controlChanged:)];
    [contentView addSubview:_emotionCheck];

    // 4. Emotion Picker (indented)
    NSTextField *emotionLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(48, 181, 75, 20)];
    [emotionLabel setStringValue:@"标记表情:"];
    [emotionLabel setFont:[NSFont systemFontOfSize:12]];
    [emotionLabel setBezeled:NO];
    [emotionLabel setDrawsBackground:NO];
    [emotionLabel setEditable:NO];
    [emotionLabel setSelectable:NO];
    [contentView addSubview:emotionLabel];

    _emotionPopup = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(125, 178, 250, 25) pullsDown:NO];
    for (const auto &item : kEmotionOptions) {
        NSMenuItem *menuItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithUTF8String:item.name]
                                                           action:nil
                                                    keyEquivalent:@""];
        [menuItem setRepresentedObject:[NSString stringWithUTF8String:item.code]];
        [[_emotionPopup menu] addItem:menuItem];
    }
    [_emotionPopup setTarget:self];
    [_emotionPopup setAction:@selector(controlChanged:)];
    [contentView addSubview:_emotionPopup];

    // 5. Sound Alert Switch
    _soundCheck = [[NSButton alloc] initWithFrame:NSMakeRect(24, 142, 390, 22)];
    [_soundCheck setButtonType:NSButtonTypeSwitch];
    [_soundCheck setTitle:@"拦截撤回时播放系统提示音"];
    [_soundCheck setFont:[NSFont systemFontOfSize:13]];
    [_soundCheck setTarget:self];
    [_soundCheck setAction:@selector(controlChanged:)];
    [contentView addSubview:_soundCheck];

    // 6. System Notification Switch
    _notifCheck = [[NSButton alloc] initWithFrame:NSMakeRect(24, 112, 390, 22)];
    [_notifCheck setButtonType:NSButtonTypeSwitch];
    [_notifCheck setTitle:@"拦截撤回时弹出系统通知横幅"];
    [_notifCheck setFont:[NSFont systemFontOfSize:13]];
    [_notifCheck setTarget:self];
    [_notifCheck setAction:@selector(controlChanged:)];
    [contentView addSubview:_notifCheck];

    // Bottom Separator
    NSBox *sep2 = [[NSBox alloc] initWithFrame:NSMakeRect(24, 98, 392, 1)];
    [sep2 setBoxType:NSBoxSeparator];
    [contentView addSubview:sep2];

    // Shortcut Help Tip
    NSTextField *tipLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(24, 72, 390, 18)];
    [tipLabel setStringValue:@"💡 提示：在钉钉任意窗口中按快捷键 ⌘\\ 可随时打开本设置。"];
    [tipLabel setFont:[NSFont systemFontOfSize:11]];
    [tipLabel setTextColor:[NSColor secondaryLabelColor]];
    [tipLabel setBezeled:NO];
    [tipLabel setDrawsBackground:NO];
    [tipLabel setEditable:NO];
    [tipLabel setSelectable:NO];
    [contentView addSubview:tipLabel];

    // 7. Action Buttons
    NSButton *logBtn = [[NSButton alloc] initWithFrame:NSMakeRect(24, 20, 105, 32)];
    [logBtn setTitle:@"查看日志"];
    [logBtn setBezelStyle:NSBezelStyleRounded];
    [logBtn setTarget:self];
    [logBtn setAction:@selector(openLogFile:)];
    [contentView addSubview:logBtn];

    NSButton *updateBtn = [[NSButton alloc] initWithFrame:NSMakeRect(138, 20, 115, 32)];
    [updateBtn setTitle:@"🔄 检查更新..."];
    [updateBtn setBezelStyle:NSBezelStyleRounded];
    [updateBtn setTarget:self];
    [updateBtn setAction:@selector(checkUpdate:)];
    [contentView addSubview:updateBtn];

    NSButton *closeBtn = [[NSButton alloc] initWithFrame:NSMakeRect(320, 20, 96, 32)];
    [closeBtn setTitle:@"确定"];
    [closeBtn setBezelStyle:NSBezelStyleRounded];
    [closeBtn setKeyEquivalent:@"\r"];
    [closeBtn setTarget:self];
    [closeBtn setAction:@selector(closeWindow:)];
    [contentView addSubview:closeBtn];
}

- (void)updateUIFromConfig {
    pthread_mutex_lock(&g_config_mutex);
    bool en = g_config.enabled;
    bool em = g_config.attach_emotion;
    bool sound = g_config.play_sound;
    bool notif = g_config.show_notification;
    std::string emotionCode = g_config.emotion_name;
    uint32_t count = g_intercepted_count;
    pthread_mutex_unlock(&g_config_mutex);

    [_enabledCheck setState:en ? NSControlStateValueOn : NSControlStateValueOff];
    [_emotionCheck setState:em ? NSControlStateValueOn : NSControlStateValueOff];
    [_soundCheck setState:sound ? NSControlStateValueOn : NSControlStateValueOff];
    [_notifCheck setState:notif ? NSControlStateValueOn : NSControlStateValueOff];
    [_emotionPopup setEnabled:em];

    NSString *curCodeStr = [NSString stringWithUTF8String:emotionCode.c_str()];
    for (NSMenuItem *item in [_emotionPopup itemArray]) {
        if ([[item representedObject] isEqualToString:curCodeStr]) {
            [_emotionPopup selectItem:item];
            break;
        }
    }

    [_statusLabel setStringValue:[NSString stringWithFormat:@"运行状态: 拦截已就绪 (已拦截 %u 条撤回消息)", count]];
}

- (void)controlChanged:(id)sender {
    (void)sender;
    pthread_mutex_lock(&g_config_mutex);
    g_config.enabled = ([_enabledCheck state] == NSControlStateValueOn);
    g_config.attach_emotion = ([_emotionCheck state] == NSControlStateValueOn);
    g_config.play_sound = ([_soundCheck state] == NSControlStateValueOn);
    g_config.show_notification = ([_notifCheck state] == NSControlStateValueOn);

    NSMenuItem *selItem = [_emotionPopup selectedItem];
    if (selItem && [selItem representedObject]) {
        g_config.emotion_name = [[selItem representedObject] UTF8String];
    }
    bool em = g_config.attach_emotion;
    pthread_mutex_unlock(&g_config_mutex);

    [_emotionPopup setEnabled:em];
    SaveConfig();
}

- (void)openLogFile:(id)sender {
    (void)sender;
    const char *logPath = "/tmp/ddrevoke.log";
    FILE *fp = fopen(logPath, "a");
    if (fp) fclose(fp);
    NSString *pathStr = [NSString stringWithUTF8String:logPath];
    [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:pathStr]];
}

- (void)checkUpdate:(id)sender {
    (void)sender;
    [[DDRevokeUpdateManager sharedManager] checkForUpdates:YES];
}

- (void)closeWindow:(id)sender {
    (void)sender;
    [self.window orderOut:nil];
}

- (void)showSettingsWindow {
    [self updateUIFromConfig];
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

@end

// ============================================================================
// Remote Update Manager (Online Version Check, Download & Zero-Touch Hot Patch)
// ============================================================================

static NSString *const kCurrentVersion = @"1.0.3";

@implementation DDRevokeUpdateManager {
    BOOL _isChecking;
}

+ (instancetype)sharedManager {
    static DDRevokeUpdateManager *s_instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_instance = [[DDRevokeUpdateManager alloc] init];
    });
    return s_instance;
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:title];
        [alert setInformativeText:msg];
        [alert addButtonWithTitle:@"确定"];
        [alert setAlertStyle:NSAlertStyleInformational];
        [alert runModal];
    });
}

- (void)checkForUpdates:(BOOL)manualCheck {
    if (_isChecking) {
        if (manualCheck) {
            [self showAlertWithTitle:@"检查更新中" message:@"正在获取最新版本信息，请稍候..."];
        }
        return;
    }
    _isChecking = YES;

    pthread_mutex_lock(&g_config_mutex);
    std::string updateUrlStr = g_config.update_url;
    bool autoCheck = g_config.auto_check_update;
    pthread_mutex_unlock(&g_config_mutex);

    if (!manualCheck && !autoCheck) {
        _isChecking = NO;
        return;
    }

    NSString *urlString = [NSString stringWithUTF8String:updateUrlStr.c_str()];
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        _isChecking = NO;
        if (manualCheck) {
            [self showAlertWithTitle:@"更新检查失败" message:@"更新检查地址无效，请检查配置。"];
        }
        return;
    }

    DDLog("[UPDATE] Checking for updates from %s (manual=%d)", [urlString UTF8String], manualCheck);

    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    sessionConfig.timeoutIntervalForRequest = 8.0;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:8.0];
    [request setValue:@"DDRevoke-UpdateClient/1.0" forHTTPHeaderField:@"User-Agent"];

    [[session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        (void)response;
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_isChecking = NO;
            if (error || !data) {
                if (manualCheck) {
                    NSString *errDesc = error ? [error localizedDescription] : @"网络无响应";
                    [self showAlertWithTitle:@"检查更新失败"
                                     message:[NSString stringWithFormat:@"无法连接到更新服务器: %@\n请检查网络或稍后重试。", errDesc]];
                }
                return;
            }

            NSError *jsonErr = nil;
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonErr];
            if (![json isKindOfClass:[NSDictionary class]]) {
                if (manualCheck) {
                    [self showAlertWithTitle:@"检查更新失败" message:@"服务器返回的版本信息格式不正确。"];
                }
                return;
            }

            NSString *remoteVer = json[@"version"];
            NSString *title = json[@"title"] ?: [NSString stringWithFormat:@"DDRevoke v%@", remoteVer];
            NSString *changeLog = json[@"changeLog"] ?: @"常规性能优化与问题修复。";
            NSString *downloadUrl = json[@"downloadUrl"];
            NSString *dmgUrl = json[@"dmgUrl"];

            if (!remoteVer || [remoteVer length] == 0) {
                if (manualCheck) {
                    [self showAlertWithTitle:@"检查更新失败" message:@"未能在响应中找到版本号。"];
                }
                return;
            }

            NSComparisonResult comp = [remoteVer compare:kCurrentVersion options:NSNumericSearch];
            if (comp == NSOrderedDescending) {
                DDLog("[UPDATE] Found newer version: v%s (current: v%s)", [remoteVer UTF8String], [kCurrentVersion UTF8String]);
                [self promptUpdateWithVersion:remoteVer
                                        title:title
                                    changeLog:changeLog
                                  downloadUrl:downloadUrl
                                       dmgUrl:dmgUrl];
            } else {
                DDLog("[UPDATE] Already up to date (current: v%s, remote: v%s)", [kCurrentVersion UTF8String], [remoteVer UTF8String]);
                if (manualCheck) {
                    [self showAlertWithTitle:@"已是最新版本"
                                     message:[NSString stringWithFormat:@"当前版本 (v%@) 已是最新版本，无需更新。", kCurrentVersion]];
                }
            }
        });
    }] resume];
}

- (void)promptUpdateWithVersion:(NSString *)ver
                          title:(NSString *)title
                      changeLog:(NSString *)changeLog
                    downloadUrl:(NSString *)downloadUrl
                         dmgUrl:(NSString *)dmgUrl {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:[NSString stringWithFormat:@"🎉 发现新版本: v%@", ver]];
    [alert setInformativeText:[NSString stringWithFormat:@"%@\n\n【更新日志】\n%@\n\n选择“立即热更新”可自动下载并静默替换插件（无需重新获取系统授权，秒级完成）。", title, changeLog]];
    [alert addButtonWithTitle:@"立即热更新 (推荐)"];
    [alert addButtonWithTitle:@"稍后再说"];
    if (dmgUrl && [dmgUrl length] > 0) {
        [alert addButtonWithTitle:@"下载完整 DMG..."];
    }

    NSModalResponse resp = [alert runModal];
    if (resp == NSAlertFirstButtonReturn) {
        [self performRemoteUpdateWithUrl:downloadUrl targetVersion:ver];
    } else if (resp == NSAlertThirdButtonReturn) {
        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:dmgUrl]];
    }
}

- (void)performRemoteUpdateWithUrl:(NSString *)downloadUrl targetVersion:(NSString *)targetVer {
    if (!downloadUrl || [downloadUrl length] == 0) {
        [self showAlertWithTitle:@"更新失败" message:@"未提供动态库下载链接，请前往 GitHub 下载完整安装包。"];
        return;
    }

    NSString *destPath = @"/Applications/DingTalk.app/Contents/MacOS/libDDRevoke.dylib";
    NSBundle *bundle = [NSBundle mainBundle];
    if (bundle && [bundle bundlePath]) {
        NSString *inBundle = [[bundle bundlePath] stringByAppendingPathComponent:@"Contents/MacOS/libDDRevoke.dylib"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:inBundle]) {
            destPath = inBundle;
        }
    }

    DDLog("[UPDATE] Starting download from %s -> destination: %s", [downloadUrl UTF8String], [destPath UTF8String]);

    NSURL *url = [NSURL URLWithString:downloadUrl];
    NSURLSession *session = [NSURLSession sharedSession];
    NSURLSessionDownloadTask *task = [session downloadTaskWithURL:url completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
        (void)response;
        if (error || !location) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self showAlertWithTitle:@"下载失败"
                                 message:[NSString stringWithFormat:@"下载更新文件失败: %@\n请检查网络连接。", [error localizedDescription]]];
            });
            return;
        }

        NSError *readErr = nil;
        NSData *fileData = [NSData dataWithContentsOfURL:location options:0 error:&readErr];
        if (!fileData || [fileData length] < 10240) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self showAlertWithTitle:@"校验失败" message:@"下载的更新文件体积异常，更新已中止。"];
            });
            return;
        }

        const uint32_t *magicPtr = (const uint32_t *)[fileData bytes];
        if (*magicPtr != 0xfeedfacf && *magicPtr != 0xcffaedfe) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self showAlertWithTitle:@"校验失败" message:@"下载的文件不是有效的 macOS 动态链接库，更新已中止。"];
            });
            return;
        }

        NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"libDDRevoke_new.dylib"];
        [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
        if (![fileData writeToFile:tmpPath atomically:YES]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self showAlertWithTitle:@"写入失败" message:@"无法写入临时文件目录。"];
            });
            return;
        }

        // Ad-hoc sign the downloaded dylib
        NSTask *csTask = [[NSTask alloc] init];
        [csTask setLaunchPath:@"/usr/bin/codesign"];
        [csTask setArguments:@[@"--force", @"--sign", @"-", tmpPath]];
        [csTask launch];
        [csTask waitUntilExit];

        NSError *copyErr = nil;
        [[NSFileManager defaultManager] removeItemAtPath:destPath error:nil];
        BOOL copyOk = [[NSFileManager defaultManager] copyItemAtPath:tmpPath toPath:destPath error:&copyErr];
        [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (copyOk) {
                DDLog("[UPDATE] Successfully installed new dylib v%s to %s", [targetVer UTF8String], [destPath UTF8String]);
                NSAlert *successAlert = [[NSAlert alloc] init];
                [successAlert setMessageText:@"🎉 更新安装成功！"];
                [successAlert setInformativeText:[NSString stringWithFormat:
                    @"DDRevoke 已成功热更新至 v%@。\n\n主程序二进制未做任何改动，系统各项权限（麦克风、摄像头、通知等）均完好保留，无需重新授权。\n\n是否立即重启钉钉以生效？", targetVer]];
                [successAlert addButtonWithTitle:@"立即重启钉钉"];
                [successAlert addButtonWithTitle:@"稍后自行重启"];
                NSModalResponse choice = [successAlert runModal];
                if (choice == NSAlertFirstButtonReturn) {
                    [self restartDingTalk];
                }
            } else {
                DDLog("[UPDATE] [ERROR] Failed to overwrite %s: %s", [destPath UTF8String], [[copyErr localizedDescription] UTF8String]);
                [self showAlertWithTitle:@"安装失败"
                                 message:[NSString stringWithFormat:@"覆盖目标动态库失败: %@\n请检查写入权限或使用 DMG 安装器更新。", [copyErr localizedDescription]]];
            }
        });
    }];
    [task resume];
}

- (void)restartDingTalk {
    NSString *appPath = [[NSBundle mainBundle] bundlePath];
    if (!appPath || [appPath length] == 0) {
        appPath = @"/Applications/DingTalk.app";
    }
    pid_t pid = getpid();
    NSString *script = [NSString stringWithFormat:
        @"/bin/sh -c 'while kill -0 %d 2>/dev/null; do sleep 0.2; done; open \"%@\"'",
        pid, appPath];
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/sh"];
    [task setArguments:@[@"-c", script]];
    [task launch];
    [NSApp terminate:nil];
}

@end

// ============================================================================
// Menu Bar Manager (Injects into macOS Top Menu & DingTalk App Submenu)
// ============================================================================

@interface DDRevokeMenuManager : NSObject <NSMenuDelegate>
+ (instancetype)sharedManager;
- (void)installMenu;
@end

@implementation DDRevokeMenuManager

+ (instancetype)sharedManager {
    static DDRevokeMenuManager *s_instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_instance = [[DDRevokeMenuManager alloc] init];
    });
    return s_instance;
}

- (void)installMenu {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self installMenu];
        });
        return;
    }

    NSMenu *mainMenu = [NSApp mainMenu];
    if (!mainMenu) {
        DDLog("[MENU] [WARN] [NSApp mainMenu] is nil, will retry later");
        return;
    }

    // 1. Top-Level Menu: "🛡️ 防撤回"
    if (![mainMenu itemWithTitle:@"🛡️ 防撤回"]) {
        NSMenuItem *topMenuItem = [[NSMenuItem alloc] initWithTitle:@"🛡️ 防撤回" action:nil keyEquivalent:@""];
        NSMenu *revokeMenu = [[NSMenu alloc] initWithTitle:@"🛡️ 防撤回"];
        [revokeMenu setDelegate:self];
        [topMenuItem setSubmenu:revokeMenu];

        // Preference item
        NSMenuItem *settingsItem = [[NSMenuItem alloc] initWithTitle:@"⚙️ 防撤回设置..."
                                                              action:@selector(onOpenSettings:)
                                                       keyEquivalent:@"\\"];
        [settingsItem setKeyEquivalentModifierMask:NSEventModifierFlagCommand];
        [settingsItem setTarget:self];
        [revokeMenu addItem:settingsItem];

        [revokeMenu addItem:[NSMenuItem separatorItem]];

        // Fast toggles
        NSMenuItem *toggleRevoke = [[NSMenuItem alloc] initWithTitle:@"启用防撤回"
                                                              action:@selector(onToggleRevoke:)
                                                       keyEquivalent:@""];
        [toggleRevoke setTarget:self];
        [toggleRevoke setState:g_config.enabled ? NSControlStateValueOn : NSControlStateValueOff];
        [revokeMenu addItem:toggleRevoke];

        NSMenuItem *toggleEmotion = [[NSMenuItem alloc] initWithTitle:@"自动贴表情标记"
                                                               action:@selector(onToggleEmotion:)
                                                        keyEquivalent:@""];
        [toggleEmotion setTarget:self];
        [toggleEmotion setState:g_config.attach_emotion ? NSControlStateValueOn : NSControlStateValueOff];
        [revokeMenu addItem:toggleEmotion];

        [revokeMenu addItem:[NSMenuItem separatorItem]];

        // Intercepted counter status
        NSMenuItem *countItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"已拦截撤回: %u 条", g_intercepted_count]
                                                           action:nil
                                                    keyEquivalent:@""];
        [countItem setEnabled:NO];
        [revokeMenu addItem:countItem];

        // Open log
        NSMenuItem *logItem = [[NSMenuItem alloc] initWithTitle:@"📂 查看运行日志"
                                                         action:@selector(onOpenLog:)
                                                  keyEquivalent:@""];
        [logItem setTarget:self];
        [revokeMenu addItem:logItem];

        // Check for updates
        NSMenuItem *updateItem = [[NSMenuItem alloc] initWithTitle:@"🔄 检查更新..."
                                                            action:@selector(onCheckUpdate:)
                                                     keyEquivalent:@""];
        [updateItem setTarget:self];
        [revokeMenu addItem:updateItem];

        // About
        NSMenuItem *aboutItem = [[NSMenuItem alloc] initWithTitle:@"ℹ️ 关于 DDRevoke"
                                                           action:@selector(onAbout:)
                                                    keyEquivalent:@""];
        [aboutItem setTarget:self];
        [revokeMenu addItem:aboutItem];

        [mainMenu addItem:topMenuItem];
        DDLog("[MENU] Successfully added top-level '🛡️ 防撤回' to main menu bar");
    }

    // 2. Insert into "钉钉" application menu (item 0) right after preferences
    if ([mainMenu numberOfItems] > 0) {
        NSMenuItem *appItem = [mainMenu itemAtIndex:0];
        if (appItem && [appItem hasSubmenu]) {
            NSMenu *appMenu = [appItem submenu];
            if (![appMenu itemWithTitle:@"🛡️ 防撤回设置..."]) {
                NSMenuItem *appSettingsItem = [[NSMenuItem alloc] initWithTitle:@"🛡️ 防撤回设置..."
                                                                         action:@selector(onOpenSettings:)
                                                                  keyEquivalent:@"\\"];
                [appSettingsItem setKeyEquivalentModifierMask:NSEventModifierFlagCommand];
                [appSettingsItem setTarget:self];

                NSInteger insertIdx = 1;
                for (NSInteger i = 0; i < [appMenu numberOfItems]; ++i) {
                    NSString *title = [[appMenu itemAtIndex:i] title];
                    if ([title containsString:@"设置"] || [title containsString:@"Preferences"]) {
                        insertIdx = i + 1;
                        break;
                    }
                }
                [appMenu insertItem:appSettingsItem atIndex:insertIdx];
                DDLog("[MENU] Successfully inserted '🛡️ 防撤回设置...' into app submenu at index %ld", (long)insertIdx);
            }
        }
    }
}

- (void)menuNeedsUpdate:(NSMenu *)menu {
    pthread_mutex_lock(&g_config_mutex);
    bool en = g_config.enabled;
    bool em = g_config.attach_emotion;
    uint32_t count = g_intercepted_count;
    pthread_mutex_unlock(&g_config_mutex);

    for (NSMenuItem *item in [menu itemArray]) {
        if ([[item title] isEqualToString:@"启用防撤回"]) {
            [item setState:en ? NSControlStateValueOn : NSControlStateValueOff];
        } else if ([[item title] isEqualToString:@"自动贴表情标记"]) {
            [item setState:em ? NSControlStateValueOn : NSControlStateValueOff];
        } else if ([[item title] containsString:@"已拦截撤回"]) {
            [item setTitle:[NSString stringWithFormat:@"已拦截撤回: %u 条", count]];
        }
    }
}

- (void)onOpenSettings:(id)sender {
    (void)sender;
    [[DDRevokeSettingsWindowController sharedController] showSettingsWindow];
}

- (void)onToggleRevoke:(NSMenuItem *)sender {
    pthread_mutex_lock(&g_config_mutex);
    g_config.enabled = !g_config.enabled;
    bool en = g_config.enabled;
    pthread_mutex_unlock(&g_config_mutex);
    [sender setState:en ? NSControlStateValueOn : NSControlStateValueOff];
    SaveConfig();
}

- (void)onToggleEmotion:(NSMenuItem *)sender {
    pthread_mutex_lock(&g_config_mutex);
    g_config.attach_emotion = !g_config.attach_emotion;
    bool em = g_config.attach_emotion;
    pthread_mutex_unlock(&g_config_mutex);
    [sender setState:em ? NSControlStateValueOn : NSControlStateValueOff];
    SaveConfig();
}

- (void)onOpenLog:(id)sender {
    (void)sender;
    const char *logPath = "/tmp/ddrevoke.log";
    FILE *fp = fopen(logPath, "a");
    if (fp) fclose(fp);
    NSString *pathStr = [NSString stringWithUTF8String:logPath];
    [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:pathStr]];
}

- (void)onCheckUpdate:(id)sender {
    (void)sender;
    [[DDRevokeUpdateManager sharedManager] checkForUpdates:YES];
}

- (void)onAbout:(id)sender {
    (void)sender;
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"DDRevoke v1.0.3"];
    [alert setInformativeText:@"钉钉 macOS 防撤回与自动表情标记补丁\n版本: 1.0.3\n快捷键: ⌘\\ 打开设置窗口\n\n已拦截撤回消息并在原消息气泡下方自动标记表情。\n支持在线一键热更新。"];
    [alert addButtonWithTitle:@"确定"];
    [alert runModal];
}

@end

// ============================================================================
// 8. Mach-O Image Discovery & Constructor Entry Point
// ============================================================================
static bool FindDingTalkMainImage(intptr_t *out_slide, uint8_t out_uuid[16]) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        if (hdr->filetype != MH_EXECUTE) continue;

        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "DingTalk") == nullptr) continue;

        *out_slide = _dyld_get_image_vmaddr_slide(i);

        // Parse LC_UUID
        const uint8_t *cmd_ptr = reinterpret_cast<const uint8_t *>(hdr) + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < hdr->ncmds; ++c) {
            const struct load_command *lc = reinterpret_cast<const struct load_command *>(cmd_ptr);
            if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
                const struct uuid_command *uc = reinterpret_cast<const struct uuid_command *>(lc);
                memcpy(out_uuid, uc->uuid, 16);
                return true;
            }
            cmd_ptr += lc->cmdsize;
        }
        return true;
    }
    return false;
}

__attribute__((constructor))
static void DDRevokeInit() {
    g_log = os_log_create("com.ddrevoke.dingtalk", "hook");

    uint8_t uuid[16] = {0};
    if (!FindDingTalkMainImage(&g_slide, uuid)) {
        return; // Not inside DingTalk main executable process
    }

    char uuid_str[40];
    snprintf(uuid_str, sizeof(uuid_str),
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);

    DDLog("============================================================");
    DDLog("DDRevoke v1.0.3 initializing in DingTalk (pid=%d, slide=0x%lx, UUID=%s)",
          getpid(), (unsigned long)g_slide, uuid_str);

    if (memcmp(uuid, DT901::kExpectedUUID, 16) != 0) {
        DDLog("[WARN] Binary UUID (%s) differs from DingTalk 9.0.1 (58780930); prolog checks will guard hooks.",
              uuid_str);
    }

    // Load persisted preferences or initialize defaults
    LoadConfig();

    InstallObjCSwizzles();

    InstallInlineHook64(
        "OnRecallMsgV3Success",
        Rebase(DT901::kVA_OnRecallMsgV3Success),
        DT901::kProlog_OnRecallMsgV3Success,
        reinterpret_cast<void *>(&Hook_OnRecallMsgV3Success),
        reinterpret_cast<void **>(&g_orig_OnRecallMsgV3Success)
    );

    InstallInlineHook64(
        "RecallMessageByMsgId",
        Rebase(DT901::kVA_RecallMessageByMsgId),
        DT901::kProlog_RecallMessageByMsgId,
        reinterpret_cast<void *>(&Hook_RecallMessageByMsgId),
        reinterpret_cast<void **>(&g_orig_RecallMessageByMsgId)
    );

    InstallInlineHook64(
        "IMMessageCache::UpdateRecallStatus",
        Rebase(DT901::kVA_UpdateRecallStatus),
        DT901::kProlog_UpdateRecallStatus,
        reinterpret_cast<void *>(&Hook_UpdateRecallStatus),
        reinterpret_cast<void **>(&g_orig_UpdateRecallStatus)
    );

    InstallInlineHook64(
        "SyncRecallCache::InRecallCache",
        Rebase(DT901::kVA_InRecallCache),
        DT901::kProlog_InRecallCache,
        reinterpret_cast<void *>(&Hook_InRecallCache),
        reinterpret_cast<void **>(&g_orig_InRecallCache)
    );

    // Register observers and delayed triggers to inject Menu Bar UI into AppKit
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] addObserverForName:NSApplicationDidFinishLaunchingNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification * _Nonnull note) {
            (void)note;
            DDLog("[MENU] NSApplicationDidFinishLaunchingNotification received, installing menu");
            [[DDRevokeMenuManager sharedManager] installMenu];
        }];

        [[NSNotificationCenter defaultCenter] addObserverForName:NSApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification * _Nonnull note) {
            (void)note;
            [[DDRevokeMenuManager sharedManager] installMenu];
        }];

        // Schedule delayed fallback installation triggers (300ms, 1000ms, 2500ms, 5000ms)
        for (int delay_ms : {300, 1000, 2500, 5000}) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay_ms * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
                [[DDRevokeMenuManager sharedManager] installMenu];
            });
        }

        // Silent background check for updates 6 seconds after launch
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[DDRevokeUpdateManager sharedManager] checkForUpdates:NO];
        });
    });

    DDLog("DDRevoke v1.0.3 initialization complete. Log file: /tmp/ddrevoke.log");
}
