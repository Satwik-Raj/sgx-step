#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
// #include <asm/tlbflush.h>

#define DEVICE_NAME "abit_probe"

/* IOCTLs */
#define IOCTL_CHECK  _IOWR('a', 'a', struct query)
#define IOCTL_CLEAR  _IOW('a', 'b', struct query)

struct query {
    pid_t pid;
    unsigned long addr;
    int accessed;
};

/* Walk page table */
static pte_t *get_pte(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd)) return NULL;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d)) return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud)) return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd)) return NULL;

    return pte_offset_map(pmd, addr);
}

/* Check accessed bit */
static int check_accessed(pid_t pid, unsigned long addr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    pte_t *pte;
    int accessed = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) return -1;

    mm = get_task_mm(task);
    if (!mm) return -1;

    down_read(&mm->mmap_lock);

    pte = get_pte(mm, addr);
    if (pte && pte_present(*pte)) {
        accessed = pte_young(*pte) ? 1 : 0;
        pte_unmap(pte);
    }

    up_read(&mm->mmap_lock);
    mmput(mm);

    return accessed;
}

/* Clear accessed bit */
static void clear_accessed(pid_t pid, unsigned long addr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    pte_t *pte;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) return;

    mm = get_task_mm(task);
    if (!mm) return;

    down_write(&mm->mmap_lock);

    pte = get_pte(mm, addr);
    if (pte && pte_present(*pte)) {

        if (pte_young(*pte)) {
            set_pte_at(mm, addr, pte, pte_mkold(*pte));
        }

        pte_unmap(pte);
    }

    up_write(&mm->mmap_lock);
    mmput(mm);
}

/* IOCTL handler */
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct query q;

    if (copy_from_user(&q, (void __user *)arg, sizeof(q)))
        return -EFAULT;

    if (cmd == IOCTL_CHECK) {
        q.accessed = check_accessed(q.pid, q.addr);

        if (copy_to_user((void __user *)arg, &q, sizeof(q)))
            return -EFAULT;
    }
    else if (cmd == IOCTL_CLEAR) {
        clear_accessed(q.pid, q.addr);
    }

    return 0;
}

static struct file_operations fops = {
    .unlocked_ioctl = device_ioctl,
};

static int major;

static int __init init_mod(void)
{
    major = register_chrdev(0, DEVICE_NAME, &fops);
    printk("abit_probe loaded\n");
    printk("Major: %d\n", major);
    return 0;
}

static void __exit exit_mod(void)
{
    unregister_chrdev(major, DEVICE_NAME);
    printk("abit_probe unloaded\n");
}

module_init(init_mod);
module_exit(exit_mod);
MODULE_LICENSE("GPL");