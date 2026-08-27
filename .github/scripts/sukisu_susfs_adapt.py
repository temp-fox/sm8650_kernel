from pathlib import Path
from textwrap import dedent

def read(path):
    return Path(path).read_text()

def write(path, data):
    Path(path).write_text(data)

def replace(path, old, new):
    p = Path(path)
    data = p.read_text()
    if old not in data:
        raise SystemExit(f"missing expected text in {path}: {old[:120]!r}")
    p.write_text(data.replace(old, new))

def append_once(path, marker, text):
    p = Path(path)
    data = p.read_text()
    if marker not in data:
        p.write_text(data.rstrip() + "\n\n" + text.strip() + "\n")

# susfs4oki 的 GKI patch 使用 static_key_true ABI；SukiSU v4.1.3 原生 sucompat 是 bool。
# 这里只在 common 已打补丁源码中把判断桥接回 SukiSU 原生 bool，避免改动原 SukiSU feature 开关模型。
for rel in ("common/fs/exec.c", "common/fs/open.c", "common/fs/stat.c"):
    p = Path(rel)
    data = p.read_text()
    data = data.replace("extern struct static_key_true ksu_su_compat_enabled;", "extern bool ksu_su_compat_enabled;")
    data = data.replace("static_branch_likely(&ksu_su_compat_enabled)", "ksu_su_compat_enabled")
    p.write_text(data)

# susfs4oki 在 VFS 层调用的 ksu_handle_{execveat,faccessat,stat} 用的是
# struct filename ** ABI（原版 KernelSU 的形态）。SukiSU v4.1.3 里
# ksu_handle_faccessat / ksu_handle_stat 已有真实实现，签名是 const char __user **，
# 由 tracepoint 在 syscall 层调用；execve 侧只有 ksu_handle_execve_sucompat，
# 没有 ksu_handle_execveat。同名会 conflicting types 直接编译失败，改名接管则会
# 抢掉 SukiSU 原生的 su 授权入口。
#
# 因此把 susfs 侧这三处调用点改指到 sucompat.c 中新增的独立桥接函数，
# 两条链路各走各的：syscall 层归 SukiSU 原生，VFS 层归 susfs 桥接。
replace(
    "common/fs/exec.c",
    "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n\t\t\tvoid *envp, int *flags);\nextern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv,\n\t\t\t\tvoid *envp, int *flags);",
    "extern int sukisu_susfs_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n\t\t\tvoid *envp, int *flags);",
)
# susfs 原本按 sdcard 是否解密分成 ksu_handle_execveat / _sucompat 两支，
# 那是原版 KernelSU 才有的区分（一支带 ksud 注入，一支不带）。SukiSU v4.1.3 的
# ksud 注入由原生 __NR_execve hook 负责，VFS 层这两支要做的事完全相同，
# 因此收成一次桥接调用，避免留下两支同调用的死分支。
replace(
    "common/fs/exec.c",
    "\t\tif (static_branch_unlikely(&susfs_is_sdcard_android_data_not_decrypted))\n\t\t\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n\t\telse\n\t\t\tksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);",
    "\t\tsukisu_susfs_handle_execveat(&fd, &filename, &argv, &envp, &flags);",
)
# 上面收掉分支后这个 extern 在 exec.c 里已无人引用，属于本次改动产生的孤儿声明，
# 一并清掉；susfs 自己的 fs/susfs.c 仍然定义并在别处使用该 static key。
replace(
    "common/fs/exec.c",
    "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;\n",
    "",
)
replace(
    "common/fs/open.c",
    "extern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode, int *__unused_flags);",
    "extern int sukisu_susfs_handle_faccessat(int *dfd, struct filename **filename, int *mode, int *__unused_flags);",
)
replace(
    "common/fs/open.c",
    "\t\t\tksu_handle_faccessat(&dfd, &fname, &mode, NULL);",
    "\t\t\tsukisu_susfs_handle_faccessat(&dfd, &fname, &mode, NULL);",
)
replace(
    "common/fs/stat.c",
    "extern int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);",
    "extern int sukisu_susfs_handle_stat(int *dfd, struct filename **filename, int *flags);",
)
replace(
    "common/fs/stat.c",
    "\t\t\tksu_handle_stat(&dfd, &filename, &flags);",
    "\t\t\tsukisu_susfs_handle_stat(&dfd, &filename, &flags);",
)

replace(
    "common/kernel/sys.c",
    "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);",
    "extern int sukisu_handle_setresuid_susfs(uid_t ruid, uid_t euid, uid_t suid);",
)
replace(
    "common/kernel/sys.c",
    "(void)ksu_handle_setresuid(ruid, euid, suid);",
    "(void)sukisu_handle_setresuid_susfs(ruid, euid, suid);",
)

kconfig = Path("KernelSU/kernel/Kconfig")
if "config KSU_SUSFS" not in kconfig.read_text():
    data = kconfig.read_text()
    body, tail = data.rsplit("endmenu", 1)
    kconfig.write_text(body + dedent(r'''

    config KSU_MANUAL_HOOK
        bool "Use manual hook"
        depends on KSU
        default n
        help
          Enable manual hook entry points patched into the kernel source.

    config KSU_SUSFS_SUS_SU
        bool "Enable SUSFS su compatibility hook"
        depends on KSU
        default y
        help
          Enable SUSFS su compatibility hook when not using manual syscall hooks.

    menu "KernelSU - SUSFS"

    config KSU_SUSFS
        bool "KernelSU addon - SUSFS"
        depends on KSU
        depends on THREAD_INFO_IN_TASK
        default y
        help
          Patch and enable SUSFS for KernelSU/SukiSU.

    config KSU_SUSFS_HAS_MAGIC_MOUNT
        bool "Enable Magic Mount support"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_SUS_PATH
        bool "Enable suspicious path hiding"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_SUS_MOUNT
        bool "Enable suspicious mount hiding"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
        bool "Auto add KSU default mounts"
        depends on KSU_SUSFS_SUS_MOUNT
        default y

    config KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
        bool "Auto add bind mounts"
        depends on KSU_SUSFS_SUS_MOUNT
        default y

    config KSU_SUSFS_SUS_KSTAT
        bool "Enable suspicious kstat spoofing"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_TRY_UMOUNT
        bool "Enable try umount"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
        bool "Auto add try umount for bind mounts"
        depends on KSU_SUSFS_TRY_UMOUNT
        default y

    config KSU_SUSFS_SPOOF_UNAME
        bool "Enable uname spoofing"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_ENABLE_LOG
        bool "Enable SUSFS kernel log"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
        bool "Hide KSU and SUSFS symbols"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
        bool "Spoof cmdline or bootconfig"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_OPEN_REDIRECT
        bool "Enable open redirect"
        depends on KSU_SUSFS
        default y

    config KSU_SUSFS_SUS_MAP
        bool "Enable suspicious mmap hiding"
        depends on KSU_SUSFS
        default y

    endmenu

    endmenu''') + tail)

replace(
    "KernelSU/kernel/core/init.c",
    "#include \"feature/uts_spoof.h\"\n#include \"infra/symbol_resolver.h\"",
    "#include \"feature/uts_spoof.h\"\n#include \"infra/symbol_resolver.h\"\n\n#ifdef CONFIG_KSU_SUSFS\nextern void susfs_init(void);\n#endif",
)
replace(
    "KernelSU/kernel/core/init.c",
    "    ksu_syscall_hook_init();\n\n    ksu_feature_init();",
    "    ksu_syscall_hook_init();\n\n#ifdef CONFIG_KSU_SUSFS\n    susfs_init();\n#endif\n\n    ksu_feature_init();",
)

append_once("KernelSU/kernel/feature/sucompat.c", "sukisu_susfs_vfs_bridge", r'''
#ifdef CONFIG_KSU_SUSFS
/*
 * sukisu_susfs_vfs_bridge
 *
 * susfs4oki 的 GKI 补丁面向原版 KernelSU，它在 fs/exec.c、fs/open.c、fs/stat.c
 * 里拿到的是已经解析好的 struct filename *，所以声明的是
 * ksu_handle_{execveat,faccessat,stat}(..., struct filename **, ...)。
 *
 * SukiSU v4.1.3 走的是另一套 ABI：ksu_handle_faccessat / ksu_handle_stat 在本文件
 * 上方已有真实实现，签名是 const char __user **filename_user，由
 * hook/syscall_event_bridge.c 的 tracepoint 在 syscall 层调用；execve 侧对应的是
 * ksu_handle_execve_sucompat，根本没有 ksu_handle_execveat 这个名字。
 *
 * 两套 ABI 同名会直接编译失败（conflicting types），改名接管则会把 SukiSU 原生的
 * su 授权入口抢掉。因此这里用独立名字提供 susfs 需要的那一组入口，并把 susfs 补丁
 * 里的三处调用点改指到这里，让两条链路各走各的：
 *   - syscall 层的 su 拦截仍由 SukiSU 原生 tracepoint 独占；
 *   - VFS 层这三个入口只做 susfs 需要的 su -> sh 改写，不碰 ksud 注入、不做
 *     root profile 逃逸，避免像上一版那样把 SukiSU 的授权状态机跑两遍。
 *
 * 注意：这不是空实现掩盖问题。SUSFS 自身的功能函数（susfs_init、sus_path、
 * sus_kstat、uname 伪装、reboot 命令分发等）都是真实实现，不在此列。
 */
static bool sukisu_susfs_filename_is_su(struct filename *fname)
{
    static const char su[] = SU_PATH;

    if (unlikely(!fname) || IS_ERR(fname) || unlikely(!fname->name))
        return false;

    return !strncmp(fname->name, su, sizeof(su));
}

/*
 * 把已解析的 filename 从 /system/bin/su 改写成 /system/bin/sh。
 * 只在 sukisu_susfs_filename_is_su() 判定成立后调用，此时 name 至少已有
 * sizeof(SU_PATH) 字节可写，而 SH_PATH 比 SU_PATH 短一个字符，因此原地覆盖
 * 连结尾 NUL 一起写入也不会越界。
 */
static void sukisu_susfs_filename_su_to_sh(struct filename *fname)
{
    static const char sh[] = SH_PATH;

    BUILD_BUG_ON(sizeof(sh) > sizeof(SU_PATH));

    memcpy((char *)fname->name, sh, sizeof(sh));
}

int sukisu_susfs_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
    if (unlikely(!filename_ptr))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    if (sukisu_susfs_filename_is_su(*filename_ptr)) {
        pr_info("susfs bridge: execveat su->sh!\n");
        sukisu_susfs_filename_su_to_sh(*filename_ptr);
    }

    return 0;
}

int sukisu_susfs_handle_faccessat(int *dfd, struct filename **filename_ptr, int *mode, int *__unused_flags)
{
    if (unlikely(!filename_ptr))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    if (sukisu_susfs_filename_is_su(*filename_ptr)) {
        pr_info("susfs bridge: faccessat su->sh!\n");
        sukisu_susfs_filename_su_to_sh(*filename_ptr);
    }

    return 0;
}

int sukisu_susfs_handle_stat(int *dfd, struct filename **filename_ptr, int *flags)
{
    if (unlikely(!filename_ptr))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    if (sukisu_susfs_filename_is_su(*filename_ptr)) {
        pr_info("susfs bridge: newfstatat su->sh!\n");
        sukisu_susfs_filename_su_to_sh(*filename_ptr);
    }

    return 0;
}
#endif
''')

replace(
    "KernelSU/kernel/runtime/ksud_integration.c",
    "#include <linux/stat.h>",
    "#include <linux/stat.h>\n#include <linux/jump_label.h>",
)
replace(
    "KernelSU/kernel/runtime/ksud_integration.c",
    "static void stop_init_rc_hook();",
    "#ifdef CONFIG_KSU_SUSFS\nDEFINE_STATIC_KEY_TRUE(ksu_is_init_rc_hook_enabled);\nDEFINE_STATIC_KEY_TRUE(ksu_is_input_hook_enabled);\n#endif\n\nstatic void stop_init_rc_hook();",
)
# SukiSU 原生 ksu_handle_sys_read 是 static 三参数函数，susfs 需要同名单参数函数，
# 同一文件内会符号冲突，因此把原生的改名，仅用于保留 SukiSU 自身的 init.rc 注入调用。
replace(
    "KernelSU/kernel/runtime/ksud_integration.c",
    "static void ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)",
    "static void ksu_handle_sys_read_sukisu(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)",
)
replace(
    "KernelSU/kernel/runtime/ksud_integration.c",
    "    ksu_handle_sys_read(fd, buf_ptr, count_ptr);\n    return orig_sys_read(regs);",
    "    ksu_handle_sys_read_sukisu(fd, buf_ptr, count_ptr);\n    return orig_sys_read(regs);",
)
replace(
    "KernelSU/kernel/runtime/ksud_integration.c",
    "static void stop_init_rc_hook()\n{\n    ksu_syscall_table_unhook(__NR_read);",
    "static void stop_init_rc_hook()\n{\n#ifdef CONFIG_KSU_SUSFS\n    if (static_key_enabled(&ksu_is_init_rc_hook_enabled))\n        static_branch_disable(&ksu_is_init_rc_hook_enabled);\n#endif\n    ksu_syscall_table_unhook(__NR_read);",
)
replace(
    "KernelSU/kernel/runtime/ksud_integration.c",
    "    input_hook_stopped = true;\n    bool ret = schedule_work(&stop_input_hook_work);",
    "    input_hook_stopped = true;\n#ifdef CONFIG_KSU_SUSFS\n    if (static_key_enabled(&ksu_is_input_hook_enabled))\n        static_branch_disable(&ksu_is_input_hook_enabled);\n#endif\n    bool ret = schedule_work(&stop_input_hook_work);",
)
append_once("KernelSU/kernel/runtime/ksud_integration.c", "sukisu_susfs_init_rc_stubs", r'''
#ifdef CONFIG_KSU_SUSFS
/*
 * sukisu_susfs_init_rc_stubs
 *
 * susfs4oki 的 fs/read_write.c 与 fs/stat.c 会调用这两个符号，用来在原版 KernelSU
 * 上完成 init.rc 注入并同步 stat 报告的文件长度。SukiSU v4.1.3 自己就 hook 了
 * __NR_read（见 stop_init_rc_hook 中的 ksu_syscall_table_unhook(__NR_read)），
 * 已经在做同一份注入。
 *
 * 这里只提供符号，不再转发到 SukiSU 的注入逻辑，也不再修改 kstat_size。重复注入会
 * 让 init.rc 内容与 stat 长度同时出错，直接影响 ksud 启动和 Manager 服务。
 */
void ksu_handle_sys_read(unsigned int fd)
{
}

void ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr)
{
}
#endif
''')

append_once("KernelSU/kernel/hook/setuid_hook.c", "sukisu_handle_setresuid_susfs", r'''
#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#include <linux/workqueue.h>

extern struct work_struct susfs_extra_works;

static void sukisu_susfs_schedule_extra_work(void)
{
    if (!work_pending(&susfs_extra_works))
        schedule_work(&susfs_extra_works);
}

/*
 * sukisu_handle_setresuid_susfs
 *
 * susfs4oki 把这个 hook 插在 __sys_setresuid() 的入口，也就是凭证尚未变更时，
 * 且无论 setresuid 最终成功还是失败都会调用一次。
 *
 * SukiSU v4.1.3 的契约完全不同：ksu_hook_setresuid 会先执行真正的 syscall，
 * 失败直接返回，成功之后才用 (old_uid, current_uid()) 调用一次 SukiSU 自己的两参数
 * setresuid 处理函数，在那里完成 Manager fd 安装、seccomp reboot allow、
 * tracepoint flag 维护和 kernel umount。
 *
 * 所以这里绝不能再调用 SukiSU 的两参数 setresuid 处理函数，否则那整套授权状态机
 * 每次 setresuid 都会跑两遍，其中一遍还在错误的凭证上下文里，会破坏 Manager 识别和
 * App Profile 授权。这个函数只负责 SUSFS 自己的隐藏标记。
 */
int sukisu_handle_setresuid_susfs(uid_t ruid, uid_t euid, uid_t suid)
{
    uid_t new_uid = (uid_t)-1;

    if (euid != (uid_t)-1)
        new_uid = euid;
    else if (ruid != (uid_t)-1)
        new_uid = ruid;
    else if (suid != (uid_t)-1)
        new_uid = suid;

    if (new_uid == (uid_t)-1)
        return 0;

    /* Manager 与已授权 UID 不打任何 SUSFS 标记，避免挡住 su 授权链路。 */
    if (is_uid_manager(new_uid) || ksu_is_allow_uid_for_current(new_uid))
        return 0;

    if (is_isolated_process(new_uid)) {
        susfs_set_current_proc_no_su();
        susfs_set_current_proc_umounted();
        sukisu_susfs_schedule_extra_work();
    } else if (unlikely(new_uid == WEBVIEW_ZYGOTE_UID)) {
        if (ksu_uid_should_umount(new_uid)) {
            susfs_set_current_proc_no_su();
            susfs_set_current_proc_umounted();
            sukisu_susfs_schedule_extra_work();
        } else {
            susfs_set_current_proc_no_su();
        }
    } else if (likely(is_appuid(new_uid)) && ksu_uid_should_umount(new_uid)) {
        susfs_set_current_proc_no_su();
        susfs_set_current_proc_umounted();
        sukisu_susfs_schedule_extra_work();
    } else {
        susfs_set_current_proc_no_su();
    }

    return 0;
}
#endif
''')

append_once("KernelSU/kernel/selinux/selinux.c", "susfs_is_current_ksu_domain", r'''
#ifdef CONFIG_KSU_SUSFS
bool susfs_is_current_ksu_domain(void)
{
    return is_ksu_domain();
}
#endif
''')

append_once("KernelSU/kernel/supercall/supercall.c", "ksu_handle_sys_reboot", r'''
#ifdef CONFIG_KSU_SUSFS
#include <linux/cred.h>
#include <linux/susfs.h>
#include <linux/susfs_def.h>

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
    if (magic1 != KSU_INSTALL_MAGIC1)
        return 1;

    if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {
        switch (cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
        case CMD_SUSFS_ADD_SUS_PATH:
            susfs_add_sus_path(arg);
            return 0;
        case CMD_SUSFS_ADD_SUS_PATH_LOOP:
            susfs_add_sus_path_loop(arg);
            return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
        case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
            susfs_set_hide_sus_mnts_for_non_su_procs(arg);
            return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
        case CMD_SUSFS_ADD_SUS_KSTAT:
        case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
            susfs_add_sus_kstat(arg);
            return 0;
        case CMD_SUSFS_UPDATE_SUS_KSTAT:
            susfs_update_sus_kstat(arg);
            return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
        case CMD_SUSFS_SET_UNAME:
            susfs_set_uname(arg);
            return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
        case CMD_SUSFS_ENABLE_LOG:
            susfs_enable_log(arg);
            return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
        case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
            susfs_set_cmdline_or_bootconfig(arg);
            return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
        case CMD_SUSFS_ADD_OPEN_REDIRECT:
            susfs_add_open_redirect(arg);
            return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
        case CMD_SUSFS_ADD_SUS_MAP:
            susfs_add_sus_map(arg);
            return 0;
#endif
        case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
            susfs_set_avc_log_spoofing(arg);
            return 0;
        case CMD_SUSFS_SHOW_ENABLED_FEATURES:
            susfs_get_enabled_features(arg);
            return 0;
        case CMD_SUSFS_SHOW_VARIANT:
            susfs_show_variant(arg);
            return 0;
        case CMD_SUSFS_SHOW_VERSION:
            susfs_show_version(arg);
            return 0;
        default:
            return 1;
        }
    }

    return 1;
}
#endif
''')
