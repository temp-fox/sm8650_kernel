from pathlib import Path
from textwrap import dedent

# 内核源码一律按 UTF-8 读写，并强制 LF 行尾。
# 不指定 encoding 时 Python 会跟随平台默认（Linux 是 UTF-8，Windows 是 GBK），
# 本脚本注入的注释含中文，在 Windows 上本地验证会把整个文件重写成 GBK。
# newline="" 则是防止 write_text 在 Windows 上把 \n 翻成 \r\n 污染内核源码。
ENC = "utf-8"

def read(path):
    return Path(path).read_text(encoding=ENC)

def write(path, data):
    Path(path).write_text(data, encoding=ENC, newline="")

def replace(path, old, new):
    p = Path(path)
    data = p.read_text(encoding=ENC)
    if old not in data:
        raise SystemExit(f"missing expected text in {path}: {old[:120]!r}")
    p.write_text(data.replace(old, new), encoding=ENC, newline="")

def append_once(path, marker, text):
    p = Path(path)
    data = p.read_text(encoding=ENC)
    if marker not in data:
        p.write_text(data.rstrip() + "\n\n" + text.strip() + "\n", encoding=ENC, newline="")

# susfs4oki 的 GKI patch 使用 static_key_true ABI；SukiSU v4.1.3 原生 sucompat 是 bool。
# 这里只在 common 已打补丁源码中把判断桥接回 SukiSU 原生 bool，避免改动原 SukiSU feature 开关模型。
for rel in ("common/fs/exec.c", "common/fs/open.c", "common/fs/stat.c"):
    p = Path(rel)
    data = p.read_text(encoding=ENC)
    data = data.replace("extern struct static_key_true ksu_su_compat_enabled;", "extern bool ksu_su_compat_enabled;")
    data = data.replace("static_branch_likely(&ksu_su_compat_enabled)", "ksu_su_compat_enabled")
    p.write_text(data, encoding=ENC, newline="")

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
if "config KSU_SUSFS" not in kconfig.read_text(encoding=ENC):
    data = kconfig.read_text(encoding=ENC)
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

    endmenu''') + tail, encoding=ENC, newline="")

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
 * 这里不能直接调用 SukiSU v4.1.3 的两参数 setresuid 处理函数：它按“真正
 * setresuid 已成功执行之后”的状态设计，会再做 kernel umount 等后置逻辑。
 * 但也不能只做 SUSFS 标记。Manager 进程的 seccomp 过滤器默认不允许 reboot(142)，
 * 如果这里不提前把 __NR_reboot 加入 SukiSU 的 seccomp allow cache，后续
 * libksud.so debug su 调用 reboot supercall 时会先被 seccomp 杀掉，根本进不了
 * kprobe 或 sys_reboot 里的 SUSFS 处理，表现就是 SUSFS 设置页卡死。
 *
 * 因此本函数只搬运 SukiSU handler 中与“Manager/已授权 app 可正常发起 supercall”
 * 直接相关的部分：放行 reboot、设置 tracepoint flag、给 Manager 安装 fd。
 * 普通 app 仍只走 SUSFS 自己的 no_su / umount 标记。
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

    if (unlikely(is_uid_manager(new_uid))) {
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        ksu_set_task_tracepoint_flag(current);
        spin_unlock_irq(&current->sighand->siglock);

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
            spin_unlock_irq(&current->sighand->siglock);
        }
        ksu_set_task_tracepoint_flag(current);
        return 0;
    }

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

# ---------------------------------------------------------------------------
# susfs selinux 符号可见性：susfs4oki 是一对配对补丁
#
# 50_add_susfs_in_gki-*.patch 打在 common/ 上，会往 security/selinux/avc.c、
# hooks.c、selinuxfs.c 里插入 extern 声明并直接引用这批符号；
# 10_enable_susfs_for_ksu.patch 打在 KernelSU/ 上，负责把这批符号从
# static 改成全局可见，并补上两个 sid 变量。
#
# 我们只打了前者（后者是面向原版 KernelSU 的整体改造，硬打会砸掉 SukiSU 的
# hook 架构），于是链接阶段必然缺符号。上一轮 CI 就在这里失败，报了 8 个
# undefined symbol：susfs_ksu_sid、susfs_priv_app_sid、ksu_selinux_hide_running、
# fake_state、ksu_selinux_hide_enabled、fake_status、initialize_fake_status、
# fake_status_initialize_key。
#
# 下面只补这 8 个符号，且严格分成两类处理：
#   1. selinux_hide.c 里已有真实实现、只是被 static 挡住的 6 个 —— 只去掉
#      static，一个字节的逻辑都不改；
#   2. SukiSU 里完全不存在的 2 个 sid —— 按 10_enable_susfs_for_ksu.patch 的
#      真实实现补齐，不是空 stub。
#
# 注意 fake_state 在 v4.1.3 里位于 #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
# 的 #else 分支内。本项目内核是 6.1.115，走的正是 #else，所以它确实会被编译
# 进来；这也是 avc.c/selinuxfs.c 能引用到它的前提。
# ---------------------------------------------------------------------------

for _old, _new in (
    ("static bool ksu_selinux_hide_enabled __read_mostly = false;",
     "bool ksu_selinux_hide_enabled __read_mostly = false;"),
    ("static bool ksu_selinux_hide_running __read_mostly = false;",
     "bool ksu_selinux_hide_running __read_mostly = false;"),
    ("static struct selinux_state fake_state;",
     "struct selinux_state fake_state;"),
    ("static DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);",
     "DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);"),
    ("static struct page *fake_status = NULL;",
     "struct page *fake_status = NULL;"),
    ("static void initialize_fake_status()",
     "void initialize_fake_status()"),
):
    replace("KernelSU/kernel/feature/selinux_hide.c", _old, _new)

# susfs 的 avc.c 补丁要拿 ksu 域和 priv_app 域的 sid 做 AVC 日志伪装。
# 这两个变量 SukiSU 侧没有，按 10_enable_susfs_for_ksu.patch 的原实现补齐，
# 并在策略加载完成后（apply_kernelsu_rules 末尾）解析一次。
append_once("KernelSU/kernel/selinux/selinux.c", "susfs_set_batch_sid", r'''
#ifdef CONFIG_KSU_SUSFS
/*
 * susfs 的 security/selinux/avc.c 补丁需要这两个 sid 来伪装 AVC 拒绝日志：
 * 命中 ksu 域时把 tcontext 报成 priv_app，避免应用侧探测到 ksu 域的存在。
 *
 * 与 SukiSU 自己的 cached_su_sid 分开保存：cached_su_sid 服务于 is_ksu_domain()
 * 的快速判定，走 KERNEL_SU_CONTEXT；这里额外需要 priv_app 域，而且解析时机
 * 挂在 apply_kernelsu_rules() 之后（策略已换新），两者互不干扰。
 *
 * 解析失败保持 0。avc.c 里的比较是 sad->tsid == susfs_ksu_sid，而 tsid 为 0
 * 不是合法的进程域 sid，所以 0 值只会让伪装静默失效，不会误伤正常日志。
 */
#define KERNEL_PRIV_APP_DOMAIN "u:r:priv_app:s0:c512,c768"

u32 susfs_ksu_sid __read_mostly = 0;
u32 susfs_priv_app_sid __read_mostly = 0;

static void susfs_set_sid(const char *secctx_name, u32 *out_sid)
{
    int err;

    err = security_secctx_to_secid(secctx_name, strlen(secctx_name), out_sid);
    if (err) {
        pr_err("susfs: failed setting sid for '%s', err: %d\n", secctx_name, err);
        *out_sid = 0;
        return;
    }
    pr_info("susfs: sid '%u' is set for secctx_name '%s'\n", *out_sid, secctx_name);
}

void susfs_set_batch_sid(void)
{
    susfs_set_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid);
    susfs_set_sid(KERNEL_PRIV_APP_DOMAIN, &susfs_priv_app_sid);
}
#endif
''')

replace(
    "KernelSU/kernel/selinux/selinux.h",
    "extern u32 ksu_file_sid;\n",
    "extern u32 ksu_file_sid;\n"
    "\n"
    "#ifdef CONFIG_KSU_SUSFS\n"
    "extern u32 susfs_ksu_sid;\n"
    "extern u32 susfs_priv_app_sid;\n"
    "void susfs_set_batch_sid(void);\n"
    "#endif\n",
)

# 在策略换新、AVC 缓存重置之后解析 sid：此时新策略已生效，
# security_secctx_to_secid() 才能查到 ksu 域。
replace(
    "KernelSU/kernel/selinux/rules.c",
    "    reset_avc_cache();\nout_unlock:\n    mutex_unlock(&selinux_state.policy_mutex);\n}",
    "    reset_avc_cache();\n"
    "#ifdef CONFIG_KSU_SUSFS\n"
    "    susfs_set_batch_sid();\n"
    "#endif\n"
    "out_unlock:\n    mutex_unlock(&selinux_state.policy_mutex);\n}",
)

# ---------------------------------------------------------------------------
# SELinux policy 直读隐藏
#
# SukiSU v4.1.3 自带的 selinux_hide 只覆盖 /sys/fs/selinux/context、access
# 和 status。检测器直接读取 /sys/fs/selinux/policy 时，sel_open_policy()
# 仍会从当前 live policy 导出一份快照，于是能扫到 apply_kernelsu_rules()
# 追加进去的 ksu/ksu_file 以及模块追加的 magisk/droidspacesd 规则。
#
# backup_sepolicy 是 apply_kernelsu_rules() 修改 live policy 前复制出来的原始策略，
# 也是 selinux_hide 给普通 App 做 context/access 计算时使用的那份策略。这里只在
# ksu_selinux_hide_running 且调用者是普通 App UID 时，把 policy 快照来源切到
# fake_state/backup_sepolicy；root、system、shell 以及未开启 selinux_hide 时仍走原始
# live policy，避免影响系统服务、管理器和调试。
# ---------------------------------------------------------------------------

replace(
    "common/security/selinux/selinuxfs.c",
    "#include <linux/slab.h>",
    "#include <linux/slab.h>\n#include <linux/vmalloc.h>",
)

replace(
    "common/security/selinux/selinuxfs.c",
    "#include \"ima.h\"",
    "#include \"ima.h\"\n#ifdef CONFIG_KSU_SUSFS\n#include \"ss/services.h\"\n#endif",
)

replace(
    "common/security/selinux/selinuxfs.c",
    "#ifdef CONFIG_KSU_SUSFS\n"
    "extern struct selinux_state fake_state;\n"
    "extern struct page *fake_status;\n"
    "extern struct static_key_false fake_status_initialize_key;\n"
    "extern bool ksu_selinux_hide_running __read_mostly;\n"
    "extern bool ksu_selinux_hide_enabled __read_mostly;\n"
    "extern void initialize_fake_status(void);\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS",
    "#ifdef CONFIG_KSU_SUSFS\n"
    "extern struct selinux_state fake_state;\n"
    "extern struct selinux_policy *backup_sepolicy;\n"
    "extern struct page *fake_status;\n"
    "extern struct static_key_false fake_status_initialize_key;\n"
    "extern bool ksu_selinux_hide_running __read_mostly;\n"
    "extern bool ksu_selinux_hide_enabled __read_mostly;\n"
    "extern void initialize_fake_status(void);\n"
    "static int susfs_read_backup_policy(void **data, size_t *len);\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS",
)

append_once("common/security/selinux/selinuxfs.c", "susfs_read_backup_policy", r'''
#ifdef CONFIG_KSU_SUSFS
static int susfs_read_backup_policy(void **data, size_t *len)
{
    struct policy_file fp;
    int rc;

    if (!backup_sepolicy)
        return -EINVAL;

    *len = backup_sepolicy->policydb.len;
    *data = vmalloc_user(*len);
    if (!*data)
        return -ENOMEM;

    fp.data = *data;
    fp.len = *len;

    rc = policydb_write(&backup_sepolicy->policydb, &fp);
    if (rc) {
        vfree(*data);
        *data = NULL;
        *len = 0;
        return rc;
    }

    *len = (unsigned long)fp.data - (unsigned long)*data;
    return 0;
}
#endif
''')

replace(
    "common/security/selinux/selinuxfs.c",
    "\trc = security_read_policy(state, &plm->data, &plm->len);\n"
    "\tif (rc)\n"
    "\t\tgoto err;",
    "#ifdef CONFIG_KSU_SUSFS\n"
    "\tif (likely(current_uid().val >= 10000 && ksu_selinux_hide_running && backup_sepolicy))\n"
    "\t\trc = susfs_read_backup_policy(&plm->data, &plm->len);\n"
    "\telse\n"
    "#endif\n"
    "\t\trc = security_read_policy(state, &plm->data, &plm->len);\n"
    "\tif (rc)\n"
    "\t\tgoto err;",
)

# =============================================================================
# SUSFS 设置页卡死的修复
#
# 【症状】管理器能正常用，但一进 SUSFS 设置页就卡死。
#
# 【根因】开启 SUSFS 后，同一次 syscall(SYS_reboot, ...) 上会有两条路径：
#
#   1. v4.1.3 自带的 kprobe，挂在 __arm64_sys_reboot 入口，先触发。
#      它认 KSU_INSTALL_MAGIC2，把 fd 安装排进 task_work。
#
#   2. susfs 的 50_add_susfs_in_gki 补丁往 SYSCALL_DEFINE4(reboot) 函数体
#      开头插的调用，随后执行：
#          ret = ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#          if (ret) goto orig_flow;   // 非 0 → 继续走真正的 reboot
#          return ret;                // 0   → 已处理，直接返回用户态
#
#   而本脚本注入的 ksu_handle_sys_reboot 原先**只认 SUSFS_MAGIC**。管理器用
#   KSU_INSTALL_MAGIC2 请求装 fd 时，会落到末尾 return 1 → goto orig_flow →
#   掉进真正的 sys_reboot → 被 CAP_SYS_BOOT 拦掉，返回 -EPERM。
#
#   结果是状态不一致：fd 其实已由 kprobe 的 task_work 装好了，但 syscall 的
#   返回值是失败，管理器据此判定授权失败。
#
# 【为什么偏偏是 SUSFS 页】
#   管理器的 SuSFSManager.getInstalledApps() 会对每个已安装 app 并发起一个
#   root shell 作业（async + awaitAll），几十上百次请求全部命中这条失败路径，
#   页面就卡住了。别的页面没有这种密集 root 请求，所以不明显。
#
# 【修法】对齐 builtin 分支 —— 该分支没有这个问题，因为它压根不注册 kprobe，
#   而是把 fd 安装并入 ksu_handle_sys_reboot，只保留一条路径。
#   这里照做：开 SUSFS 时停用 kprobe，由注入的函数独占处理。
#
#   只在 CONFIG_KSU_SUSFS 下改变行为；不开 SUSFS 时 kprobe 照常注册，
#   与未打补丁的 v4.1.3 逐字节等价。
# =============================================================================

replace(
    "KernelSU/kernel/supercall/supercall.c",
    "void __init ksu_supercalls_init(void)\n"
    "{\n"
    "    int rc;\n",
    "void __init ksu_supercalls_init(void)\n"
    "{\n"
    "#ifndef CONFIG_KSU_SUSFS\n"
    "    int rc;\n"
    "#endif\n",
)

replace(
    "KernelSU/kernel/supercall/supercall.c",
    "    rc = register_kprobe(&reboot_kp);\n"
    "    if (rc) {\n"
    "        pr_err(\"reboot kprobe failed: %d\\n\", rc);\n"
    "    } else {\n"
    "        pr_info(\"reboot kprobe registered successfully\\n\");\n"
    "    }",
    "#ifdef CONFIG_KSU_SUSFS\n"
    "    /*\n"
    "     * 开启 SUSFS 时不注册 kprobe：susfs 补丁已经在 SYSCALL_DEFINE4(reboot)\n"
    "     * 函数体里直接调用 ksu_handle_sys_reboot()，那条路径同时处理 SUSFS 命令\n"
    "     * 和管理器的 fd 安装请求。两条路径并存会让 fd 装两次，且 syscall 返回值\n"
    "     * 与实际结果不一致 —— 这正是 SUSFS 设置页卡死的原因。\n"
    "     * builtin 分支同样不注册 kprobe，此处与之对齐。\n"
    "     */\n"
    "    pr_info(\"susfs enabled, reboot handled in syscall body (kprobe skipped)\\n\");\n"
    "#else\n"
    "    rc = register_kprobe(&reboot_kp);\n"
    "    if (rc) {\n"
    "        pr_err(\"reboot kprobe failed: %d\\n\", rc);\n"
    "    } else {\n"
    "        pr_info(\"reboot kprobe registered successfully\\n\");\n"
    "    }\n"
    "#endif",
)

# 开 SUSFS 时上面两处引用都被编译掉，reboot_kp 就成了「定义但未使用」的 static
# 变量，触发 -Wunused-variable；内核带 -Werror 时直接编译失败。
# 加 __maybe_unused 消掉。reboot_handler_pre 仍被 reboot_kp 的初始化式引用，
# 不受影响，不用动。
replace(
    "KernelSU/kernel/supercall/supercall.c",
    "static struct kprobe reboot_kp = {",
    "static struct kprobe __maybe_unused reboot_kp = {",
)

replace(
    "KernelSU/kernel/supercall/supercall.c",
    "    unregister_kprobe(&reboot_kp);\n",
    "#ifndef CONFIG_KSU_SUSFS\n"
    "    unregister_kprobe(&reboot_kp);\n"
    "#endif\n",
)

# ⚠️ 幂等标记必须选一个只可能出现在「被追加内容」里的串。
#    这里曾用 "ksu_handle_sys_reboot"，结果上面 kprobe 注释里也提到了这个函数名，
#    标记被提前命中，append_once 以为已经追加过 —— 整个 reboot 处理函数根本没注入，
#    SUSFS 命令通道直接失效。改用函数定义的完整签名，注释里不会出现。
append_once("KernelSU/kernel/supercall/supercall.c",
            "int ksu_handle_sys_reboot(int magic1", r'''
#ifdef CONFIG_KSU_SUSFS
#include <linux/cred.h>
#include <linux/susfs.h>
#include <linux/susfs_def.h>

/*
 * 管理器安装 ksu fd 的处理，与文件上方 reboot_handler_pre() 里的 kprobe 路径同源。
 * 开启 SUSFS 时 kprobe 已被停用（见下方 register_kprobe 的条件编译），由本函数独占。
 */
static int ksu_supercall_reboot_handler_susfs(void __user **arg)
{
    struct ksu_install_fd_tw *tw;

    tw = kzalloc(sizeof(*tw), GFP_KERNEL);
    if (!tw)
        return 0;

    /*
     * 补丁调用点传的是 &arg，所以 *arg 才是 syscall 的第 4 个参数，
     * 与 kprobe 路径里的 PT_REGS_SYSCALL_PARM4(real_regs) 等价。
     */
    tw->outp = (int __user *)(*arg);
    tw->cb.func = ksu_install_fd_tw_func;

    if (task_work_add(current, &tw->cb, TWA_RESUME)) {
        kfree(tw);
        pr_warn("install fd add task_work failed\n");
    }

    return 0;
}

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
    if (magic1 != KSU_INSTALL_MAGIC1)
        return 1;

    /*
     * 管理器请求安装 ksu fd。必须返回 0，让补丁的调用点直接 return，
     * 不要 goto orig_flow —— 那条路会被 CAP_SYS_BOOT 拒掉。
     */
    if (magic2 == KSU_INSTALL_MAGIC2)
        return ksu_supercall_reboot_handler_susfs(arg);

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
