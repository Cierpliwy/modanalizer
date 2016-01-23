/*-----------------------------------------------------------------------------
    This file is part of Linux Kernel Module Analizer
    Copyright (C) 2013  Przemysław Lenart <przemek.lenart@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see [http://www.gnu.org/licenses/].
-----------------------------------------------------------------------------*/
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>

MODULE_AUTHOR("Przemyslaw Lenart <przemek.lenart@gmail.com>");
MODULE_DESCRIPTION("Module analizer - module functions calls counter");
MODULE_VERSION("0.4");
MODULE_LICENSE("GPL");

/* --------------------------- Module defines -------------------------------*/
#define MODULE_NAME_STR "modanalizer"
#define MODULE_PRINTK KERN_ERR MODULE_NAME_STR ": "
static char *module_name = "";

/* ----------------------------- Parameters ---------------------------------*/
module_param(module_name, charp, 0000);
MODULE_PARM_DESC(module_name, "Module name to analyze");

/* --------------------------- Data structures ------------------------------*/
struct ma_symbol_data
{
        struct kprobe kp;
        atomic_long_t calls;
        char *name;
        unsigned long long size;
};

static struct ma_symbol_data *ma_symbols = NULL;
static unsigned int ma_symbols_count = 0;

/* -------------------------- Sequence file ---------------------------------*/
static void *ma_seq_start(struct seq_file *s, loff_t *pos)
{
        if (*pos >= ma_symbols_count) return NULL;
        return &ma_symbols[*pos];
}

static void *ma_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
        if (*pos + 1 >= ma_symbols_count) return NULL;
        return &ma_symbols[++*pos];
}

static void ma_seq_stop(struct seq_file *s, void *v)
{

}

static int ma_seq_show(struct seq_file *s, void *v)
{
        struct ma_symbol_data *data = (struct ma_symbol_data*) v;
        seq_printf(s, "%ld\t%p\t%llu\t%s\n", 
                      atomic_long_read(&data->calls), 
                      data->kp.addr,
                      data->size, data->name);
        return 0;
}

static struct seq_operations ma_seq_ops = {
        .start = ma_seq_start,
        .next = ma_seq_next,
        .stop = ma_seq_stop,
        .show = ma_seq_show
};

static int ma_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &ma_seq_ops);
}

static struct file_operations ma_file_ops = {
        .owner = THIS_MODULE,
        .open = ma_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = seq_release
};

/* --------------------------- Kprobes handler ----------------------------- */
static int ma_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
        struct ma_symbol_data *data =
                container_of(p, struct ma_symbol_data, kp);
        atomic_long_inc(&data->calls);
        return 0;
}

/* ----------------------------- Entry point ------------------------------- */
static int __init init_modanalizer(void)
{
        struct module *mod_ptr;
        unsigned int i,j;

        mutex_lock(&module_mutex);
        mod_ptr = find_module(module_name);
        mutex_unlock(&module_mutex);

        if (!mod_ptr) {
                printk(MODULE_PRINTK "Module doesn't exist\n");
                return -EINVAL;
        }

        printk(MODULE_PRINTK "Found module: %s\n", mod_ptr->name);

        /* Count all text symbols */
        ma_symbols_count = 0;
        for(i = 0; i < mod_ptr->num_symtab; ++i) {
                Elf64_Sym *sym = &mod_ptr->symtab[i];
                if (sym->st_info == 't' || sym->st_info == 'T')
                        ma_symbols_count++;
        }

        printk(MODULE_PRINTK "Getting text symbols (%u)...\n",
               ma_symbols_count);

        ma_symbols = kmalloc(sizeof(*ma_symbols) * ma_symbols_count,
                             GFP_KERNEL);
        if (!ma_symbols) {
                printk(MODULE_PRINTK "Not enough memory to allocate symbols\n");
                return -ENOMEM;
        }

        /* Clear all memory */
        memset(ma_symbols, 0, sizeof(*ma_symbols) * ma_symbols_count);

        /* Get all symbols - TODO: Not sure if some lock is required there */
        for (i = 0, j = 0; i < mod_ptr->num_symtab; ++i) {
                Elf64_Sym *sym;

                sym = &mod_ptr->symtab[i];
                if (sym->st_info != 't' && sym->st_info != 'T')
                        continue;


                ma_symbols[j].kp.addr = (kprobe_opcode_t*) (sym->st_value);
                ma_symbols[j].kp.pre_handler = ma_pre_handler;
                ma_symbols[j].name = mod_ptr->strtab + sym->st_name;
                ma_symbols[j].size = sym->st_size;

                printk(MODULE_PRINTK "%u: %s\n", j, ma_symbols[j].name);

                if (register_kprobe(&ma_symbols[j].kp) < 0) {
                        printk(MODULE_PRINTK
                               "Couldn't register kprobe for function: %s\n",
                               ma_symbols[j].name);
                        ma_symbols[j].kp.addr = NULL;
                }
                ++j;
        }

        if (!proc_create(MODULE_NAME_STR, 0644, NULL, &ma_file_ops)) {
                printk(MODULE_PRINTK "Couldn't create procfs file\n");
                kfree(ma_symbols);
                return -ENOMEM;
        }

        return 0;
}

static void __exit exit_modanalizer(void)
{
        unsigned int i;
        remove_proc_entry(MODULE_NAME_STR, NULL);

        for (i = 0; i < ma_symbols_count; ++i)
                if (ma_symbols[i].kp.addr)
                        unregister_kprobe(&ma_symbols[i].kp);

        kfree(ma_symbols);
}

module_init(init_modanalizer);
module_exit(exit_modanalizer);
