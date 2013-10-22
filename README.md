# MODULE ANALIZER
Przemysław Lenart <przemek.lenart@gmail.com>

v. 0.4, 2013

## Description

Linux kernel module analizer is a kernel module designed for monitoring in real time
selected module's functions call count. It can be used to check activity of certain
functions in module, get their addresses and sizes.

To install module simply type:
	
	insmod modanalizer.ko module_name=xxx

To monitor Intel's wifi driver you can type:

	insmod modanalizer.ko module_name=iwlwifi

Results can be seen by reading `/proc/modanalizer` file. Example output can look
like this:

	...
	0	ffffffffa03577b0	172	iwl_pcie_free_dma_ptr.isra.25
	6	ffffffffa0357990	2063	iwl_pcie_enqueue_hcmd
	230	ffffffffa035a990	22	iwl_trans_pcie_write8
	642	ffffffffa035a9b0	22	iwl_trans_pcie_write32
	51	ffffffffa035a9d0	22	iwl_trans_pcie_read32
	0	ffffffffa035a9f0	49	iwl_trans_pcie_read_prph
	0	ffffffffa035aa30	49	iwl_trans_pcie_write_prph
	0	ffffffffa035aa70	13	iwl_trans_pcie_suspend
	...

There are 4 columns and they have following meaning:
1. Function call count
2. Function's address in Linux kenrel space
3. Function's size in bytes
4. Function's symbol name.

