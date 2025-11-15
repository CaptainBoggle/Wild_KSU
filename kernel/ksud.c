#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#include <linux/input-event-codes.h>
#else
#include <uapi/linux/input.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#include <linux/aio.h>
#endif
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include "allowlist.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "selinux/selinux.h"

static const char KERNEL_SU_RC[] =
	"\n"
	
	// "service zygote_secondary /system/bin/app_process32 -Xzygote /system/bin --zygote --socket-name=zygote_secondary --enable-lazy-preload\n"
	// "    class main\n"
	// "    priority -20\n"
	// "    user root\n"
	// "    group root readproc reserved_disk\n"
	// "    socket zygote_secondary stream 660 root system\n"
	// "    socket usap_pool_secondary stream 660 root system\n"
	// "    onrestart restart zygote\n"
	// "    task_profiles ProcessCapacityHigh MaxPerformance\n"

	// "\n"
	
	"on post-fs-data\n"
	"    start logd\n"
	// We should wait for the post-fs-data finish
	"    exec u:r:su:s0 root -- " KSUD_PATH " post-fs-data\n"

	"\n"
	
	// "on zygote-start\n"
	// "    start zygote_secondary\n"

	// "\n"

	"on nonencrypted\n"
	"    exec u:r:su:s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec u:r:su:s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:sys.boot_completed=1\n"
	"    exec u:r:su:s0 root -- " KSUD_PATH " boot-completed\n"
	"\n"

	"\n";

static const char KERNEL_SU_INIT_IMPORT[] =
	"import /system/etc/init/hw/init.zygote64_32.rc\n";

static void stop_vfs_read_hook();
static void stop_execve_hook();
static void stop_input_hook();

#ifdef CONFIG_KSU_KPROBES_HOOK
static struct work_struct stop_vfs_read_work;
static struct work_struct stop_execve_hook_work;
static struct work_struct stop_input_hook_work;
#else
bool ksu_vfs_read_hook __read_mostly = true;
bool ksu_execveat_hook __read_mostly = true;
bool ksu_input_hook __read_mostly = true;
#endif

u32 ksu_devpts_sid;

#ifdef CONFIG_COMPAT
bool ksu_is_compat __read_mostly = false;
#endif

void on_post_fs_data(void)
{
	static bool done = false;
	if (done) {
		pr_info("on_post_fs_data already done\n");
		return;
	}
	done = true;
	pr_info("on_post_fs_data!\n");
	ksu_load_allow_list();
	// sanity check, this may influence the performance
	stop_input_hook();

	ksu_devpts_sid = ksu_get_devpts_sid();
	pr_info("devpts sid: %d\n", ksu_devpts_sid);
}

#define MAX_ARG_STRINGS 0x7FFFFFFF
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		ksu_is_compat = true;
		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

/*
 * count() counts the number of strings in array ARGV.
 */

/*
 * Make sure old GCC compiler can use __maybe_unused,
 * Test passed in 4.4.x ~ 4.9.x when use GCC.
 */

static int __maybe_unused count(struct user_arg_ptr argv, int max)
{
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;
			++i;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

// IMPORTANT NOTE: the call from execve_handler_pre WON'T provided correct value for envp and flags in GKI version
int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
			     struct user_arg_ptr *argv,
			     struct user_arg_ptr *envp, int *flags)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_execveat_hook) {
		return 0;
	}
#endif
	struct filename *filename;

	static const char app_process[] = "/system/bin/app_process";
	static bool first_app_process = true;

	/* This applies to versions Android 10+ */
	static const char system_bin_init[] = "/system/bin/init";
	/* This applies to versions between Android 6 ~ 9  */
	static const char old_system_init[] = "/init";
	static bool init_second_stage_executed = false;

	if (!filename_ptr)
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (unlikely(!memcmp(filename->name, system_bin_init,
			     sizeof(system_bin_init) - 1) &&
		     argv)) {
		// /system/bin/init executed
		int argc = count(*argv, MAX_ARG_STRINGS);
		pr_info("/system/bin/init argc: %d\n", argc);
		if (argc > 1 && !init_second_stage_executed) {
			const char __user *p = get_user_arg_ptr(*argv, 1);
			if (p && !IS_ERR(p)) {
				char first_arg[16];
				ksu_strncpy_from_user_retry(
					first_arg, p, sizeof(first_arg));
				pr_info("/system/bin/init first arg: %s\n",
					first_arg);
				if (!strcmp(first_arg, "second_stage")) {
					pr_info("/system/bin/init second_stage executed\n");
					apply_kernelsu_rules();
					init_second_stage_executed = true;
					ksu_android_ns_fs_check();
				}
			} else {
				pr_err("/system/bin/init parse args err!\n");
			}
		}
	} else if (unlikely(!memcmp(filename->name, old_system_init,
				    sizeof(old_system_init) - 1) &&
			    argv)) {
		// /init executed
		int argc = count(*argv, MAX_ARG_STRINGS);
		pr_info("/init argc: %d\n", argc);
		if (argc > 1 && !init_second_stage_executed) {
			/* This applies to versions between Android 6 ~ 7 */
			const char __user *p = get_user_arg_ptr(*argv, 1);
			if (p && !IS_ERR(p)) {
				char first_arg[16];
				ksu_strncpy_from_user_retry(
					first_arg, p, sizeof(first_arg));
				pr_info("/init first arg: %s\n", first_arg);
				if (!strcmp(first_arg, "--second-stage")) {
					pr_info("/init second_stage executed\n");
					apply_kernelsu_rules();
					init_second_stage_executed = true;
					ksu_android_ns_fs_check();
				}
			} else {
				pr_err("/init parse args err!\n");
			}
		} else if (argc == 1 && !init_second_stage_executed && envp) {
			/* This applies to versions between Android 8 ~ 9  */
			int envc = count(*envp, MAX_ARG_STRINGS);
			if (envc > 0) {
				int n;
				for (n = 1; n <= envc; n++) {
					const char __user *p =
						get_user_arg_ptr(*envp, n);
					if (!p || IS_ERR(p)) {
						continue;
					}
					char env[256];
					// Reading environment variable strings from user space
					if (ksu_strncpy_from_user_retry(
						    env, p, sizeof(env)) < 0)
						continue;
					// Parsing environment variable names and values
					char *env_name = env;
					char *env_value = strchr(env, '=');
					if (env_value == NULL)
						continue;
					// Replace equal sign with string terminator
					*env_value = '\0';
					env_value++;
					// Check if the environment variable name and value are matching
					if (!strcmp(env_name,
						    "INIT_SECOND_STAGE") &&
					    (!strcmp(env_value, "1") ||
					     !strcmp(env_value, "true"))) {
						pr_info("/init second_stage executed\n");
						apply_kernelsu_rules();
						init_second_stage_executed =
							true;
						ksu_android_ns_fs_check();
					}
				}
			}
		}
	}

	if (unlikely(first_app_process && !memcmp(filename->name, app_process,
						  sizeof(app_process) - 1))) {
		first_app_process = false;
		pr_info("exec app_process, /data prepared, second_stage: %d\n",
			init_second_stage_executed);
		on_post_fs_data(); // we keep this for old ksud
		stop_execve_hook();
	}

	return 0;
}

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t read_count_append = 0;
static bool atrace_rc_inserted;
static bool init_import_inserted;
static bool vendor_build_modified;
static bool replace_file_content;
static struct file *replace_file_target;
static bool vendor_payload_in_progress;
static bool init_import_enabled = false;
static char *vendor_payload_data;
static size_t vendor_payload_len;
static size_t vendor_payload_pos;

static bool ksu_is_target_comm(const char *comm)
{
	static const char *const allowed[] = {
		"init",
		"property_service",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(allowed); ++i) {
		if (!strcmp(comm, allowed[i])) {
			return true;
		}
	}

	return false;
}

static bool ksu_line_has_prefix(const char *line, size_t len,
				    const char *prefix)
{
	size_t prefix_len = strlen(prefix);
	if (len < prefix_len) {
		return false;
	}
	return !strncmp(line, prefix, prefix_len);
}

static bool ksu_is_vendor_build_path(const char *path)
{
	static const char *const candidates[] = {
		"/vendor/build.prop",
		"/vendor/etc/build.prop",
		"/mnt/vendor/build.prop",
		"/mnt/vendor/etc/build.prop",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(candidates); ++i) {
		if (!strcmp(path, candidates[i])) {
			return true;
		}
	}

	return false;
}

static char *ksu_generate_vendor_build_payload(struct file *file,
					       size_t *out_len)
{
	char *orig = NULL;
	char *out = NULL;
	loff_t old_pos = file->f_pos;
	loff_t pos = 0;
	size_t file_size = i_size_read(file->f_path.dentry->d_inode);

	if (!file_size || file_size > SZ_64K || vendor_payload_in_progress) {
		return NULL;
	}

	vendor_payload_in_progress = true;

	orig = kmalloc(file_size + 1, GFP_KERNEL);
	if (!orig) {
		goto out;
	}

	ssize_t read_bytes = kernel_read(file, orig, file_size, &pos);
	if (read_bytes <= 0) {
		goto out;
	}
	if (read_bytes > file_size) {
		read_bytes = file_size;
	}
	size_t input_len = (size_t)read_bytes;
	orig[input_len] = '\0';

	out = kmalloc(input_len + 128, GFP_KERNEL);
	if (!out) {
		goto out;
	}

	size_t out_len_local = 0;
	char *cursor = orig;
	char *end = orig + input_len;
	while (cursor < end) {
		char *newline = memchr(cursor, '\n', end - cursor);
		size_t line_len = newline ? (size_t)(newline - cursor) : (size_t)(end - cursor);
		bool matched = false;

		if (ksu_line_has_prefix(cursor, line_len, "ro.zygote=zygote64")) {
			const char replacement[] = "ro.zygote=zygote64_32\n";
			memcpy(out + out_len_local, replacement, sizeof(replacement) - 1);
			out_len_local += sizeof(replacement) - 1;
			matched = true;
		} else if (ksu_line_has_prefix(cursor, line_len,
					      "ro.vendor.product.cpu.abilist=arm64-v8a")) {
			const char replacement[] =
				"ro.vendor.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi\n";
			memcpy(out + out_len_local, replacement, sizeof(replacement) - 1);
			out_len_local += sizeof(replacement) - 1;
			matched = true;
		} else if (ksu_line_has_prefix(cursor, line_len,
						  "ro.vendor.product.cpu.abilist32=")) {
			const char replacement[] =
				"ro.vendor.product.cpu.abilist32=armeabi-v7a,armeabi\n";
			memcpy(out + out_len_local, replacement, sizeof(replacement) - 1);
			out_len_local += sizeof(replacement) - 1;
			matched = true;
		}

		if (!matched) {
			memcpy(out + out_len_local, cursor, line_len);
			out_len_local += line_len;
			if (newline) {
				out[out_len_local++] = '\n';
			}
		}

		cursor = newline ? newline + 1 : end;
	}

	*out_len = out_len_local;
	file->f_pos = old_pos;
	vendor_payload_in_progress = false;
	kfree(orig);
	return out;

out:
	file->f_pos = old_pos;
	if (out) {
		kfree(out);
	}
	if (orig) {
		kfree(orig);
	}
	vendor_payload_in_progress = false;
	return NULL;
}

static bool ksu_all_injections_done(void)
{
	bool init_done = init_import_inserted || !init_import_enabled;
	return atrace_rc_inserted && init_done && vendor_build_modified;
}

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count,
			  loff_t *pos)
{
	bool first_read = file->f_pos == 0;
	ssize_t ret = 0;
	bool replace_active = replace_file_content && file == replace_file_target;

	if (!replace_active && orig_read) {
		ret = orig_read(file, buf, count, pos);
	}

	if (replace_active) {
		size_t remaining = vendor_payload_len - vendor_payload_pos;
		size_t chunk = min_t(size_t, count, remaining);
		if (chunk) {
			if (copy_to_user(buf, vendor_payload_data + vendor_payload_pos,
				     chunk)) {
				return -EFAULT;
			}
			vendor_payload_pos += chunk;
			file->f_pos += chunk;
			ret = chunk;
		} else {
			ret = 0;
		}
		if (vendor_payload_pos >= vendor_payload_len) {
			replace_file_content = false;
			replace_file_target = NULL;
			kfree(vendor_payload_data);
			vendor_payload_data = NULL;
			vendor_payload_len = 0;
			vendor_payload_pos = 0;
		}
		return ret;
	}

	if (first_read) {
		pr_info("read_proxy append %ld + %ld\n", ret,
			read_count_append);
		ret += read_count_append;
	}
	return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
	bool first_read = iocb->ki_pos == 0;
	ssize_t ret = 0;
	bool replace_active = replace_file_content &&
			  iocb->ki_filp == replace_file_target;

	if (!replace_active && orig_read_iter) {
		ret = orig_read_iter(iocb, to);
	}

	if (replace_active) {
		size_t remaining = vendor_payload_len - vendor_payload_pos;
		size_t chunk = min_t(size_t, iov_iter_count(to), remaining);
		if (chunk) {
			if (copy_to_iter(vendor_payload_data + vendor_payload_pos, chunk,
				        to) != chunk) {
				return -EFAULT;
			}
			vendor_payload_pos += chunk;
			iocb->ki_pos += chunk;
			ret = chunk;
		} else {
			ret = 0;
		}
		if (vendor_payload_pos >= vendor_payload_len) {
			replace_file_content = false;
			replace_file_target = NULL;
			kfree(vendor_payload_data);
			vendor_payload_data = NULL;
			vendor_payload_len = 0;
			vendor_payload_pos = 0;
		}
		return ret;
	}

	if (first_read) {
		pr_info("read_iter_proxy append %ld + %ld\n", ret,
			read_count_append);
		ret += read_count_append;
	}
	return ret;
}

int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
			size_t *count_ptr, loff_t **pos)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_vfs_read_hook) {
		return 0;
	}
#endif
	struct file *file;
	char __user *buf;
	size_t count;

	if (!ksu_is_target_comm(current->comm)) {
		// only care about init/property_service style readers
		return 0;
	}

	file = *file_ptr;
	if (IS_ERR(file)) {
		return 0;
	}

	if (!S_ISREG(file->f_path.dentry->d_inode->i_mode)) {
		return 0;
	}

	if (vendor_payload_in_progress) {
		return 0;
	}

	const char *short_name = file->f_path.dentry->d_name.name;
	if (!short_name) {
		return 0;
	}

	char path[256];
	char *dpath = d_path(&file->f_path, path, sizeof(path));

	if (IS_ERR(dpath)) {
		return 0;
	}

	const char *payload = NULL;
	char *payload_alloc = NULL;
	size_t payload_len = 0;
	bool *inserted = NULL;
	bool append_original = true;

	if (ksu_is_vendor_build_path(dpath)) {
		if (vendor_build_modified) {
			pr_info("vendor build already handled: %s\n", dpath);
			goto out_stop_check;
		}
		pr_info("intercept vendor build: %s\n", dpath);
		payload_alloc = ksu_generate_vendor_build_payload(file, &payload_len);
		if (!payload_alloc || !payload_len) {
			pr_err("failed to prepare vendor build.prop payload\n");
			goto out;
		}
		vendor_payload_data = payload_alloc;
		vendor_payload_len = payload_len;
		vendor_payload_pos = 0;
		payload_alloc = NULL;
		inserted = &vendor_build_modified;
		append_original = false;
	} else {
		size_t short_len = strlen(short_name);
		if (short_len < 3 || strcmp(short_name + short_len - 3, ".rc")) {
			goto out;
		}
		if (!strcmp(dpath, "/system/etc/init/atrace.rc")) {
			payload = KERNEL_SU_RC;
			payload_len = strlen(KERNEL_SU_RC);
			inserted = &atrace_rc_inserted;
		} else if (!strcmp(dpath, "/init.rc") ||
			   !strcmp(dpath, "/system/etc/init/init.rc")) {
			if (!init_import_enabled) {
				goto out;
			}
			payload = KERNEL_SU_INIT_IMPORT;
			payload_len = strlen(KERNEL_SU_INIT_IMPORT);
			inserted = &init_import_inserted;
		} else {
			goto out;
		}
	}

	if (*inserted) {
		goto out_stop_check;
	}

	buf = *buf_ptr;
	count = *count_ptr;

	pr_info("vfs_read inject: %s, comm: %s, count: %zu, payload: %zu\n",
		dpath, current->comm, count, payload_len);

	if (count < payload_len) {
		if (append_original) {
			pr_err("count: %zu < payload: %zu\n", count, payload_len);
			goto out;
		}
	}

	size_t ret = 0;
	if (append_original) {
		ret = copy_to_user(buf, payload, payload_len);
		if (ret) {
			pr_err("copy payload failed: %zu\n", ret);
			goto out;
		}
	}

	// we've succeed to insert our payload, now proxy the read and adjust the return size.
	if (!append_original) {
		replace_file_content = true;
		replace_file_target = file;
	}
	memcpy(&fops_proxy, file->f_op, sizeof(struct file_operations));
	orig_read = file->f_op->read;
	if (orig_read) {
		fops_proxy.read = read_proxy;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0) 
	orig_read_iter = file->f_op->read_iter;
	if (orig_read_iter) {
		fops_proxy.read_iter = read_iter_proxy;
	}
#endif
	// replace the file_operations
	file->f_op = &fops_proxy;
	read_count_append = append_original ? payload_len : 0;

	if (append_original) {
		*buf_ptr = buf + payload_len;
		*count_ptr = count - payload_len;
	}
	*inserted = true;

	out_stop_check:
	if (ksu_all_injections_done()) {
		stop_vfs_read_hook();
	}

out:
	if (payload_alloc) {
		kfree(payload_alloc);
	}
	return 0;
}

int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
			size_t *count_ptr)
{
	struct file *file = fget(fd);
	if (!file) {
		return 0;
	}
	int result = ksu_handle_vfs_read(&file, buf_ptr, count_ptr, NULL);
	fput(file);
	return result;
}

static unsigned int volumedown_pressed_count = 0;

static bool is_volumedown_enough(unsigned int count)
{
	return count >= 3;
}

int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
				  int *value)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_input_hook) {
		return 0;
	}
#endif
	if (*type == EV_KEY && *code == KEY_VOLUMEDOWN) {
		int val = *value;
		pr_info("KEY_VOLUMEDOWN val: %d\n", val);
		if (val) {
			// key pressed, count it
			volumedown_pressed_count += 1;
			if (is_volumedown_enough(volumedown_pressed_count)) {
				stop_input_hook();
			}
		}
	}

	return 0;
}

bool ksu_is_safe_mode()
{
	static bool safe_mode = false;
	if (safe_mode) {
		// don't need to check again, userspace may call multiple times
		return true;
	}

	// stop hook first!
	stop_input_hook();

	pr_info("volumedown_pressed_count: %d\n", volumedown_pressed_count);
	if (is_volumedown_enough(volumedown_pressed_count)) {
		// pressed over 3 times
		pr_info("KEY_VOLUMEDOWN pressed max times, safe mode detected!\n");
		safe_mode = true;
		return true;
	}

	return false;
}

/* 
 * ksu_handle_execve_ksud, execve_ksud handler for non kprobe
 * adapted from sys_execve_handler_pre 
 * https://github.com/tiann/KernelSU/commit/2027ac3
 */
__maybe_unused int ksu_handle_execve_ksud(const char __user *filename_user,
			const char __user *const __user *__argv)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct filename filename_in, *filename_p;
	char path[32];

#ifndef CONFIG_KSU_KPROBES_HOOK
	// return early if disabled.
	if (!ksu_execveat_hook) {
		return 0;
	}
#endif

	if (!filename_user)
		return 0;

	memset(path, 0, sizeof(path));
	ksu_strncpy_from_user_nofault(path, filename_user, 32);

	// this is because ksu_handle_execveat_ksud calls it filename->name
	filename_in.name = path;
	filename_p = &filename_in;
    
	return ksu_handle_execveat_ksud(AT_FDCWD, &filename_p, &argv, NULL, NULL);
}

#ifdef CONFIG_KSU_KPROBES_HOOK

// https://elixir.bootlin.com/linux/v5.10.158/source/fs/exec.c#L1864
static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	int *fd = (int *)&PT_REGS_PARM1(regs);
	struct filename **filename_ptr =
		(struct filename **)&PT_REGS_PARM2(regs);
	struct user_arg_ptr argv;
#ifdef CONFIG_COMPAT
	argv.is_compat = PT_REGS_PARM3(regs);
	if (unlikely(argv.is_compat)) {
		argv.ptr.compat = PT_REGS_CCALL_PARM4(regs);
	} else {
		argv.ptr.native = PT_REGS_CCALL_PARM4(regs);
	}
#else
	argv.ptr.native = PT_REGS_PARM3(regs);
#endif

	return ksu_handle_execveat_ksud(fd, filename_ptr, &argv, NULL, NULL);
}

static int sys_execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	const char __user **filename_user =
		(const char **)&PT_REGS_PARM1(real_regs);
	const char __user *const __user *__argv =
		(const char __user *const __user *)PT_REGS_PARM2(real_regs);
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct filename filename_in, *filename_p;
	char path[32];

	if (!filename_user)
		return 0;

	memset(path, 0, sizeof(path));
	ksu_strncpy_from_user_nofault(path, *filename_user, 32);
	filename_in.name = path;

	filename_p = &filename_in;
	return ksu_handle_execveat_ksud(AT_FDCWD, &filename_p, &argv, NULL,
					NULL);
}

// remove this later!
__maybe_unused static int vfs_read_handler_pre(struct kprobe *p,
					       struct pt_regs *regs)
{
	struct file **file_ptr = (struct file **)&PT_REGS_PARM1(regs);
	char __user **buf_ptr = (char **)&PT_REGS_PARM2(regs);
	size_t *count_ptr = (size_t *)&PT_REGS_PARM3(regs);
	loff_t **pos_ptr = (loff_t **)&PT_REGS_CCALL_PARM4(regs);

	return ksu_handle_vfs_read(file_ptr, buf_ptr, count_ptr, pos_ptr);
}

static int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	char __user **buf_ptr = (char __user **)&PT_REGS_PARM2(real_regs);
	size_t count_ptr = (size_t *)&PT_REGS_PARM3(real_regs);

	return ksu_handle_sys_read(fd, buf_ptr, count_ptr);
}

static int input_handle_event_handler_pre(struct kprobe *p,
					  struct pt_regs *regs)
{
	unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
	unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
	int *value = (int *)&PT_REGS_CCALL_PARM4(regs);
	return ksu_handle_input_handle_event(type, code, value);
}

#if 1
static struct kprobe execve_kp = {
	.symbol_name = SYS_EXECVE_SYMBOL,
	.pre_handler = sys_execve_handler_pre,
};
#else
static struct kprobe execve_kp = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.symbol_name = "do_execveat_common",
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
	.symbol_name = "__do_execve_file",
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	.symbol_name = "do_execveat_common",
#endif
	.pre_handler = execve_handler_pre,
};
#endif

#if 1
static struct kprobe vfs_read_kp = {
	.symbol_name = SYS_READ_SYMBOL,
	.pre_handler = sys_read_handler_pre,
};
#else
static struct kprobe vfs_read_kp = {
	.symbol_name = "vfs_read",
	.pre_handler = vfs_read_handler_pre,
};
#endif

static struct kprobe input_event_kp = {
	.symbol_name = "input_event",
	.pre_handler = input_handle_event_handler_pre,
};

static void do_stop_vfs_read_hook(struct work_struct *work)
{
	unregister_kprobe(&vfs_read_kp);
}

static void do_stop_execve_hook(struct work_struct *work)
{
	unregister_kprobe(&execve_kp);
}

static void do_stop_input_hook(struct work_struct *work)
{
	unregister_kprobe(&input_event_kp);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#include "objsec.h" // task_security_struct
bool is_ksu_transition(const struct task_security_struct *old_tsec,
			const struct task_security_struct *new_tsec)
{
	static u32 ksu_sid;
	char *secdata;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid)
		security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	
	return allowed;
}
#endif

static void stop_vfs_read_hook()
{
	if (vendor_payload_data) {
		kfree(vendor_payload_data);
		vendor_payload_data = NULL;
		vendor_payload_len = 0;
		vendor_payload_pos = 0;
	}
	replace_file_content = false;
	replace_file_target = NULL;
#ifdef CONFIG_KSU_KPROBES_HOOK
	bool ret = schedule_work(&stop_vfs_read_work);
	pr_info("unregister vfs_read kprobe: %d!\n", ret);
#else
	ksu_vfs_read_hook = false;
	pr_info("stop vfs_read_hook\n");
#endif
}

static void stop_execve_hook()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	bool ret = schedule_work(&stop_execve_hook_work);
	pr_info("unregister execve kprobe: %d!\n", ret);
#else
	ksu_execveat_hook = false;
	pr_info("stop execve_hook\n");
#endif
}

static void stop_input_hook()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	static bool input_hook_stopped = false;
	if (input_hook_stopped) {
		return;
	}
	input_hook_stopped = true;
	bool ret = schedule_work(&stop_input_hook_work);
	pr_info("unregister input kprobe: %d!\n", ret);
#else
	if (!ksu_input_hook) { return; }
	ksu_input_hook = false;
	pr_info("stop input_hook\n");
#endif
}

// ksud: module support
void ksu_ksud_init()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	int ret;

	ret = register_kprobe(&execve_kp);
	pr_info("ksud: execve_kp: %d\n", ret);

	ret = register_kprobe(&vfs_read_kp);
	pr_info("ksud: vfs_read_kp: %d\n", ret);

	ret = register_kprobe(&input_event_kp);
	pr_info("ksud: input_event_kp: %d\n", ret);

	INIT_WORK(&stop_vfs_read_work, do_stop_vfs_read_hook);
	INIT_WORK(&stop_execve_hook_work, do_stop_execve_hook);
	INIT_WORK(&stop_input_hook_work, do_stop_input_hook);
#endif
}

void ksu_ksud_exit()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	unregister_kprobe(&execve_kp);
	// this should be done before unregister vfs_read_kp
	// unregister_kprobe(&vfs_read_kp);
	unregister_kprobe(&input_event_kp);
#endif
}
