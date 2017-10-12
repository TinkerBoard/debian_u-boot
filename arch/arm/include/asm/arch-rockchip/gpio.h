/*
 * (C) Copyright 2015 Google, Inc
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#ifndef _ASM_ARCH_GPIO_H
#define _ASM_ARCH_GPIO_H

struct rockchip_gpio_regs {
	u32 swport_dr;
	u32 swport_ddr;
	u32 reserved0[(0x30 - 0x08) / 4];
	u32 inten;
	u32 intmask;
	u32 inttype_level;
	u32 int_polarity;
	u32 int_status;
	u32 int_rawstatus;
	u32 debounce;
	u32 porta_eoi;
	u32 ext_port;
	u32 reserved1[(0x60 - 0x54) / 4];
	u32 ls_sync;
};
check_member(rockchip_gpio_regs, ls_sync, 0x60);

/*
 * RK3288 IO memory map:
 *
 */
#define RKIO_GPIO0_PHYS                 0xFF750000
#define RKIO_GRF_PHYS                   0xFF770000
#define RKIO_GPIO1_PHYS                 0xFF780000
#define RKIO_GPIO2_PHYS                 0xFF790000
#define RKIO_GPIO3_PHYS                 0xFF7A0000
#define RKIO_GPIO4_PHYS                 0xFF7B0000
#define RKIO_GPIO5_PHYS                 0xFF7C0000
#define RKIO_GPIO6_PHYS                 0xFF7D0000

/* gpio power down/up control */
#define GRF_GPIO2A_P		0x150
#define GRF_GPIO6A_P		0x190

/* gpio input/output control */
#define GPIO_SWPORT_DR		0x00
#define GPIO_SWPORT_DDR		0x04
#define GPIO_EXT_PORT		0x50

#endif
