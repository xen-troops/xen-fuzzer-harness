/*
 * Copyright (c) 2024 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/arch/arm64/libafl_qemu.h>
#include <zephyr/sys/device_mmio.h>

static mm_reg_t gic_va;

void fuzz_gic(char *buf, int len)
{
	static uint32_t offs[1024];
	static uint32_t data[1024];
	int cnt = 0;
	int i;

	while (len >= 8)
	{
		memcpy(offs + cnt,  buf, sizeof(uint32_t));
		buf += sizeof(uint32_t);
		memcpy(data + cnt,  buf, sizeof(uint32_t));
		buf += sizeof(uint32_t);

		offs[cnt] = offs[cnt] % 0x20000;

		cnt++;
		len -= 8;
	}

	for ( i = 0; i < cnt; i++)
		sys_write32(data[i], gic_va + offs[i]);
}

#define BUF_SIZE 4096
static char data[BUF_SIZE];

void fuzz_hypercalls(char *buf, int len);

int main(void)
{
	uint64_t buf_size;
	data[0] = 0xff;  // init page

	lqprintf("LibAFL, hello from Zephyr test harness!\n");

	device_map(&gic_va, 0x8000000, 0x20000, K_MEM_CACHE_NONE);

	lqprintf("GIC mapped at %lx\n", gic_va);

	libafl_qemu_test();

	memset(data, 0, sizeof(data));

	buf_size = libafl_qemu_start_virt(data, BUF_SIZE);
	fuzz_hypercalls(data, buf_size);
	libafl_qemu_end(LIBAFL_QEMU_END_OK);

	return 0;
}
