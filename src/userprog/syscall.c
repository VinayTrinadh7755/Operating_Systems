#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "string.h"
#define maxium_descriptors 128
#define offsets_of_descriptors 3 


static struct file *table_for_descriptors[128][maxium_descriptors];  
static struct lock filesys_lock;

static void ssv_handler_for_syscall(struct intr_frame *);
static void syscall_for_dispatch(int number_of_syscalls, struct intr_frame *);

static void ssv_exit_handler(struct intr_frame *), 
            ssv_write_handler(struct intr_frame *), 
            ssv_read_handler(struct intr_frame *), 
            ssv_open_handler(struct intr_frame *), 
            ssv_create_handler(struct intr_frame *), 
            ssv_closer_handler(struct intr_frame *), 
            ssv_exec_handler(struct intr_frame *), 
            ssv_wait_handler(struct intr_frame *);
static void closer_ssv(int descriptors);
static int  write_ssv(int descriptors, const void *buffer, unsigned size),
            read_ssv(int descriptors, void *buffer, unsigned size),
            open_ssv(const char *file),
            wait_ssv(tid_t pid);
static bool create_ssv(const char *file, unsigned initial_size);
static tid_t exec_ssv(const char *cmd_line);
static void verify_vlptr_ssv(const void *ptr, size_t size),
             args_to_validate_ssv(const void *esp, int count),
             string_checking_ssv(const char *str);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, ssv_handler_for_syscall, "syscall");
    lock_init(&filesys_lock); int i = 0, j = 0;
init_loop_for_outer: if (i >= 128) goto done; j = 0;
init_loop_for_inner: if (j >= maxium_descriptors) { i++; goto init_loop_for_outer;}
    table_for_descriptors[i][j] = NULL; j++;
    goto init_loop_for_inner;
done: return;
}

void exit(int status) {
    struct thread *cur = thread_current();
    cur->esc_ssv = status;
    printf("%s: exit(%d)\n", cur->name, status);
    int tid = cur->tid;
    int descriptors = offsets_of_descriptors;
loop_for_cleanup:
    if (descriptors >= maxium_descriptors) goto doing_cleanup;
    if (table_for_descriptors[tid][descriptors] != NULL) {
        file_close(table_for_descriptors[tid][descriptors]);
        table_for_descriptors[tid][descriptors] = NULL;
    }
    descriptors++;
    goto doing_cleanup;
doing_cleanup: thread_exit();
}

static void string_checking_ssv(const char *str) {
    if (str == NULL) exit(-1);
    verify_vlptr_ssv(str, 1);
    const char *p = str;
checking_for_char_loop:
    verify_vlptr_ssv(p, 1);
    if (*p == '\0') goto checking_for_char_done;
    p++;
    goto checking_for_char_loop;
checking_for_char_done:
    return;
}

static void verify_vlptr_ssv(const void *ptr, size_t size) {
    uint8_t *uaddr = (uint8_t *)ptr; uint8_t *end = uaddr + size;
checking_pages_ssv: if (uaddr >= end)
        return;
    if (!is_user_vaddr(uaddr) || pagedir_get_page(thread_current()->pagedir, uaddr) == NULL) goto getting_access_invalid;
    size_t page_left = PGSIZE - ((uintptr_t)uaddr % PGSIZE);
    uaddr += (end - uaddr < page_left) ? (end - uaddr) : page_left; goto checking_pages_ssv;
getting_access_invalid:
    exit(-1);
}
static void args_to_validate_ssv(const void *esp, int count) {
    verify_vlptr_ssv(esp, sizeof(int) * (count + 1));
    int i = 0;
checking_for_arg_loop:
    if (i >= count) goto checking_for_arg_done;
    verify_vlptr_ssv((int *)esp + i + 1, sizeof(int));
    i++;
    goto checking_for_arg_loop;
checking_for_arg_done:
    return;
}

static int write_ssv(int descriptors, const void *buffer, unsigned size) {
    verify_vlptr_ssv(buffer, size);
    if (descriptors == 1) goto writing_stdout;
    int tid = thread_current()->tid;
    if (descriptors < offsets_of_descriptors || descriptors >= maxium_descriptors || table_for_descriptors[tid][descriptors] == NULL) goto invalid_descriptors;
    lock_acquire(&filesys_lock);
    int written_bytes = file_write(table_for_descriptors[tid][descriptors], buffer, size);
    lock_release(&filesys_lock);
    goto goto_written_return;
writing_stdout:
    putbuf((char *)buffer, size);
    return size;
invalid_descriptors: return -1;
goto_written_return: return written_bytes;
}
static int read_ssv(int descriptors, void *buffer, unsigned size) {
    verify_vlptr_ssv(buffer, size);
    if (descriptors == 0) goto read_ssvstdin;
    int tid = thread_current()->tid;
    if (descriptors < offsets_of_descriptors || descriptors >= maxium_descriptors ||
        table_for_descriptors[tid][descriptors] == NULL)
        goto descriptors_are_invalid;

    lock_acquire(&filesys_lock);
    int bytes_read = file_read(table_for_descriptors[tid][descriptors], buffer, size);
    lock_release(&filesys_lock);
    goto reading_return;
read_ssvstdin: { unsigned i = 0; stdinssv_loop:
    if (i >= size) goto stdinssv_done;
    ((char *)buffer)[i] = input_getc();
    i++; goto stdinssv_loop;
stdinssv_done: return size;
}
descriptors_are_invalid:return -1;
reading_return: return bytes_read;
}
static int open_ssv(const char *file) {
    string_checking_ssv(file);
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    if (f != NULL) { struct file *f_dup = file_reopen(f); file_close(f);
        f = f_dup;
    }
    lock_release(&filesys_lock);
    if (!f) goto fail_opening;
    int tid = thread_current()->tid;
    int descriptors = offsets_of_descriptors;
descriptors_searching_loop: if (descriptors >= maxium_descriptors) goto descriptors_not_free;
    if (table_for_descriptors[tid][descriptors] == NULL) { table_for_descriptors[tid][descriptors] = f;
        return descriptors;
    }
    descriptors++;
    goto descriptors_searching_loop;
descriptors_not_free:
    lock_acquire(&filesys_lock);
    file_close(f);
    lock_release(&filesys_lock);
fail_opening:
    return -1;
}
static bool create_ssv(const char *file, unsigned initial_size) { string_checking_ssv(file); lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}
static tid_t exec_ssv(const char *cmd_line) { string_checking_ssv(cmd_line);
    char *cmd_copy = palloc_get_page(0); if (cmd_copy == NULL) goto failure_exec;
    strlcpy(cmd_copy, cmd_line, PGSIZE);
    char *save_ptr; char *file_name = strtok_r(cmd_copy, " ", &save_ptr);
    if (file_name == NULL) goto its_free_fails;
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file_name);
    lock_release(&filesys_lock);
    if (f == NULL) goto its_free_fails;
    file_close(f); palloc_free_page(cmd_copy);
    return process_execute(cmd_line);
its_free_fails: palloc_free_page(cmd_copy);
failure_exec: return -1;
}
static int wait_ssv(tid_t pid) { return process_wait(pid); }

static void func_close_file_ssv(int tid, int fd) {
    lock_acquire(&filesys_lock);
    file_close(table_for_descriptors[tid][fd]);
    lock_release(&filesys_lock);
    table_for_descriptors[tid][fd] = NULL;
}
static void closer_ssv(int descriptors) {
    int tid = thread_current()->tid;
    if (descriptors < offsets_of_descriptors || descriptors >= maxium_descriptors || table_for_descriptors[tid][descriptors] == NULL) 
        return;

    func_close_file_ssv(tid, descriptors);
}
static int getting_arg_from_stack(void *esp, int index) {
    return *((int *)esp + index);
}
static void ssv_exit_handler(struct intr_frame *f) {
    args_to_validate_ssv(f->esp, 1);
    int status = getting_arg_from_stack(f->esp, 1);
    exit(status);
}
static int getting_int_arg_from_the_stack(void *esp, int index) {
    return *((int *)esp + index);
}
static void *getting_ptr_arg_the_stack(void *esp, int index) {
    return (void *)(uintptr_t)(*((uint32_t *)esp + index));
}
static unsigned getting_unsign_arg_from_the_stack(void *esp, int index) {
    return *((unsigned *)esp + index);
}
static void ssv_write_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 3);
    int descriptors = getting_int_arg_from_the_stack(f->esp, 1);
    void *buf = getting_ptr_arg_the_stack(f->esp, 2);
    unsigned size = getting_unsign_arg_from_the_stack(f->esp, 3);
    f->eax = write_ssv(descriptors, buf, size);
}
static int getting_int_arg_from_stack(void *esp, int index) {
    return *((int *)esp + index);
}
static void *gettin_ptr_arg_from_the_stack(void *esp, int index) {
    return (void *)(uintptr_t)(*((uint32_t *)esp + index));
}
static unsigned getting_unsigned_arg_from_the_stack(void *esp, int index) {
    return *((unsigned *)esp + index);
}
static void ssv_read_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 3);
    int descriptors = getting_int_arg_from_stack(f->esp, 1);
    void *buf = gettin_ptr_arg_from_the_stack(f->esp, 2);
    unsigned size = getting_unsigned_arg_from_the_stack(f->esp, 3);
    f->eax = read_ssv(descriptors, buf, size);
}
static int getting_int_arg_stack(void *esp, int index) {
    return *((int *)esp + index);
}
static void *getting_ptr_arg_from_stack(void *esp, int index) {
    return (void *)(uintptr_t)(*((uint32_t *)esp + index));
}
static void ssv_open_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 1);
    const char *file = (const char *)getting_ptr_arg_from_stack(f->esp, 1);
    f->eax = open_ssv(file);
}

static void ssv_create_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 2);
    const char *file = (const char *)*((uint32_t *)f->esp + 1);
    unsigned initial_size = *((unsigned *)f->esp + 2);
    f->eax = create_ssv(file, initial_size);
}

static int getting_arg_from_the_stack(void *esp, int index) { return *((int *)esp + index); }
static void ssv_closer_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 1);
    int fd = getting_arg_from_the_stack(f->esp, 1);
    closer_ssv(fd); f->eax = 0;
}

static const char *getting_str_arg_from_the_stack(void *esp, int index) { return (const char *)(*((uint32_t *)esp + index)); }
static void ssv_exec_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 1);
    const char *cmd_line = getting_str_arg_from_the_stack(f->esp, 1);
    f->eax = exec_ssv(cmd_line);
}

static tid_t getting_tid_arg_from_the_stack(void *esp, int index) { return *((tid_t *)esp + index); }
static void ssv_wait_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 1);
    tid_t pid = getting_tid_arg_from_the_stack(f->esp, 1);
    f->eax = wait_ssv(pid);
}

static bool removing_the_file_with_lock(const char *file) { lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);
    return success;
}
static bool sys_remove(const char *file) {
    string_checking_ssv(file);
    return removing_the_file_with_lock(file);
}


static void ssv_remove_handler(struct intr_frame *f) {
    args_to_validate_ssv(f->esp, 1);
    const char *file;
    goto arg_extraction;
arg_extraction:
    file = (const char *)*((uint32_t *)f->esp + 1);
    goto removal_of_perform;
removal_of_perform:
    f->eax = sys_remove(file);
}

static bool checking_if_valid_descriptors(int tid, int fd) {
    return fd >= offsets_of_descriptors &&
           fd < maxium_descriptors &&
           table_for_descriptors[tid][fd] != NULL;
}

static int sys_filesize(int descriptors) {
    int tid = thread_current()->tid;
    if (!checking_if_valid_descriptors(tid, descriptors)) return -1;
    lock_acquire(&filesys_lock);
    int size = file_length(table_for_descriptors[tid][descriptors]);
    lock_release(&filesys_lock);
    return size;
}

static int getting_descriptors_from_stack(void *esp) {
    return *((int *)esp + 1);
}
static void ssv_filesize_handler(struct intr_frame *f) { args_to_validate_ssv(f->esp, 1);
    int descriptors = getting_descriptors_from_stack(f->esp);
    f->eax = sys_filesize(descriptors);
}
static void seeking__ssv(int descriptors, unsigned position) { int tid = thread_current()->tid;
    if (descriptors < offsets_of_descriptors || descriptors >= maxium_descriptors ||
        table_for_descriptors[tid][descriptors] == NULL) {
        return;
    }goto seeks_and_then_acquires;
seeks_and_then_acquires: lock_acquire(&filesys_lock);
    file_seek(table_for_descriptors[tid][descriptors], position);
    goto exits_when_released;
exits_when_released: lock_release(&filesys_lock);
}

static void handling_seeking_ssv(struct intr_frame *f) { args_to_validate_ssv(f->esp, 2);
    int descriptors = *((int *)f->esp + 1); unsigned pos = *((unsigned *)f->esp + 2); seeking__ssv(descriptors, pos);
}
static unsigned telling_ssv(int descriptors) { int tid = thread_current()->tid;
    if (descriptors < offsets_of_descriptors || descriptors >= maxium_descriptors || 
        table_for_descriptors[tid][descriptors] == NULL) {
        return -1;
    } unsigned pos;
    goto recieving_and_response;
recieving_and_response: lock_acquire(&filesys_lock);
    pos = file_tell(table_for_descriptors[tid][descriptors]);
    goto leaving_and_returning;
leaving_and_returning: lock_release(&filesys_lock);
    return pos;
}


static void syscall_for_dispatch(int number_of_syscalls, struct intr_frame *f) {
    switch (number_of_syscalls) {
        case SYS_HALT:   shutdown_power_off(); break;
        case SYS_EXIT:   ssv_exit_handler(f);  break;
        case SYS_WRITE:  ssv_write_handler(f); break;
        case SYS_READ:   ssv_read_handler(f);  break;
        case SYS_OPEN:   ssv_open_handler(f);  break;
        case SYS_CREATE: ssv_create_handler(f); break;
        case SYS_CLOSE:  ssv_closer_handler(f); break;
        case SYS_EXEC:   ssv_exec_handler(f);  break;
        case SYS_WAIT:   ssv_wait_handler(f);  break;
        case SYS_REMOVE:   ssv_remove_handler(f);    break;
        case SYS_FILESIZE: ssv_filesize_handler(f);  break;
        case SYS_SEEK:     handling_seeking_ssv(f);           break;
        case SYS_TELL:     telling_ssv(f);           break;
        default:         exit(-1);             break;
    }
}

static void ssv_handler_for_syscall(struct intr_frame *f) {
    if (f->esp == NULL || !is_user_vaddr(f->esp)) exit(-1);
    verify_vlptr_ssv(f->esp, sizeof(int));
    int number_of_syscalls = *(int *)f->esp;
    syscall_for_dispatch(number_of_syscalls, f);}