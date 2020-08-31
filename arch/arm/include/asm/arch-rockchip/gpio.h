/*
 * (C) Copyright 2015 Google, Inc
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#ifndef _ASM_ARCH_GPIO_H
#define _ASM_ARCH_GPIO_H

#ifndef CONFIG_ROCKCHIP_GPIO_V2
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
#define GRF_GPIO2A_P            0x150
#define GRF_GPIO6A_P            0x190

/* gpio input/output control */
#define GPIO_SWPORT_DR          0x00
#define GPIO_SWPORT_DDR         0x04
#define GPIO_EXT_PORT           0x50

#else
struct rockchip_gpio_regs {
	u32 swport_dr_l;                        /* ADDRESS OFFSET: 0x0000 */
	u32 swport_dr_h;                        /* ADDRESS OFFSET: 0x0004 */
	u32 swport_ddr_l;                       /* ADDRESS OFFSET: 0x0008 */
	u32 swport_ddr_h;                       /* ADDRESS OFFSET: 0x000c */
	u32 int_en_l;                           /* ADDRESS OFFSET: 0x0010 */
	u32 int_en_h;                           /* ADDRESS OFFSET: 0x0014 */
	u32 int_mask_l;                         /* ADDRESS OFFSET: 0x0018 */
	u32 int_mask_h;                         /* ADDRESS OFFSET: 0x001c */
	u32 int_type_l;                         /* ADDRESS OFFSET: 0x0020 */
	u32 int_type_h;                         /* ADDRESS OFFSET: 0x0024 */
	u32 int_polarity_l;                     /* ADDRESS OFFSET: 0x0028 */
	u32 int_polarity_h;                     /* ADDRESS OFFSET: 0x002c */
	u32 int_bothedge_l;                     /* ADDRESS OFFSET: 0x0030 */
	u32 int_bothedge_h;                     /* ADDRESS OFFSET: 0x0034 */
	u32 debounce_l;                         /* ADDRESS OFFSET: 0x0038 */
	u32 debounce_h;                         /* ADDRESS OFFSET: 0x003c */
	u32 dbclk_div_en_l;                     /* ADDRESS OFFSET: 0x0040 */
	u32 dbclk_div_en_h;                     /* ADDRESS OFFSET: 0x0044 */
	u32 dbclk_div_con;                      /* ADDRESS OFFSET: 0x0048 */
	u32 reserved004c;                       /* ADDRESS OFFSET: 0x004c */
	u32 int_status;                         /* ADDRESS OFFSET: 0x0050 */
	u32 reserved0054;                       /* ADDRESS OFFSET: 0x0054 */
	u32 int_rawstatus;                      /* ADDRESS OFFSET: 0x0058 */
	u32 reserved005c;                       /* ADDRESS OFFSET: 0x005c */
	u32 port_eoi_l;                         /* ADDRESS OFFSET: 0x0060 */
	u32 port_eoi_h;                         /* ADDRESS OFFSET: 0x0064 */
	u32 reserved0068[2];                    /* ADDRESS OFFSET: 0x0068 */
	u32 ext_port;                           /* ADDRESS OFFSET: 0x0070 */
	u32 reserved0074;                       /* ADDRESS OFFSET: 0x0074 */
	u32 ver_id;                             /* ADDRESS OFFSET: 0x0078 */
};
check_member(rockchip_gpio_regs, ver_id, 0x0078);
#endif

#endif
