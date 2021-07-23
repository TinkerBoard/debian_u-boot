/*
 * (C) Copyright 2019 Rockchip Electronics Co., Ltd
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#ifndef __EVB_RV1126_H
#define __EVB_RV1126_H

#include <configs/rv1126_common.h>

#define CONFIG_SYS_MMC_ENV_DEV 0

#define ROCKCHIP_DEVICE_SETTINGS \
			"stdout=serial,vidconsole\0" \
			"stderr=serial,vidconsole\0"
#undef CONFIG_CONSOLE_SCROLL_LINES
#define CONFIG_CONSOLE_SCROLL_LINES            10

#ifndef CONFIG_SPL_BUILD
#undef CONFIG_BOOTCOMMAND

/*
 * We made a deal: Not allow U-Boot to bring up thunder-boot kernel.
 *
 * Because the thunder-boot feature may require special memory layout
 * or other appointments, U-Boot can't handle all that. Let's go back
 * to SPL to bring up kernel.
 *
 * Note: bootcmd is only called in normal boot sequence, that means
 * we allow user to boot what they want in U-Boot shell mode.
 */
#ifdef CONFIG_SPL_KERNEL_BOOT
#define CONFIG_BOOTCOMMAND "reset"
#else
#define CONFIG_BOOTCOMMAND RKIMG_BOOTCOMMAND
#endif

#define CONFIG_SET_DFU_ALT_INFO
#define DFU_ALT_BOOT_EMMC \
	"gpt raw 0x0 0x20000;" \
	"loader raw 0x20000 0xE0000;"\
	"uboot part uboot;" \
	"boot part boot;" \
	"rootfs partubi rootfs;" \
	"userdata partubi userdata\0"

#define DFU_ALT_BOOT_MTD \
	"gpt raw 0x0 0x20000;" \
	"loader raw 0x20000 0xE0000;"\
	"vnvm part vnvm;" \
	"uboot part uboot;" \
	"boot part boot;" \
	"rootfs partubi rootfs;" \
	"userdata partubi userdata\0"
#endif /* !CONFIG_SPL_BUILD */
#endif
