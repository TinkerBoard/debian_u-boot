/*
 * (C) Copyright 2018 Rockchip Electronics Co., Ltd
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <debug_uart.h>
#include <dm.h>
#include <key.h>
#include <misc.h>
#include <ram.h>
#include <spl.h>
#include <optee_include/OpteeClientInterface.h>
#include <asm/arch/bootrom.h>
#ifdef CONFIG_ROCKCHIP_PRELOADER_ATAGS
#include <asm/arch/rk_atags.h>
#endif
#include <asm/arch/gpio.h>
#include <asm/arch/sdram.h>
#include <asm/arch/boot_mode.h>
#include <asm/arch-rockchip/sys_proto.h>
#include <asm/io.h>

DECLARE_GLOBAL_DATA_PTR;

void board_return_to_bootrom(void)
{
	back_to_bootrom(BROM_BOOT_NEXTSTAGE);
}

__weak const char * const boot_devices[BROM_LAST_BOOTSOURCE + 1] = {
};

const char *board_spl_was_booted_from(void)
{
	u32  bootdevice_brom_id = readl(BROM_BOOTSOURCE_ID_ADDR);
	const char *bootdevice_ofpath = NULL;

	if (bootdevice_brom_id < ARRAY_SIZE(boot_devices))
		bootdevice_ofpath = boot_devices[bootdevice_brom_id];

	if (bootdevice_ofpath)
		debug("%s: brom_bootdevice_id %x maps to '%s'\n",
		      __func__, bootdevice_brom_id, bootdevice_ofpath);
	else
		debug("%s: failed to resolve brom_bootdevice_id %x\n",
		      __func__, bootdevice_brom_id);

	return bootdevice_ofpath;
}

u32 spl_boot_device(void)
{
	u32 boot_device = BOOT_DEVICE_MMC1;

#if defined(CONFIG_TARGET_CHROMEBOOK_JERRY) || \
		defined(CONFIG_TARGET_CHROMEBIT_MICKEY) || \
		defined(CONFIG_TARGET_CHROMEBOOK_MINNIE)
	return BOOT_DEVICE_SPI;
#endif
	if (CONFIG_IS_ENABLED(ROCKCHIP_BACK_TO_BROM))
		return BOOT_DEVICE_BOOTROM;

	return boot_device;
}

u32 spl_boot_mode(const u32 boot_device)
{
	return MMCSD_MODE_RAW;
}

__weak void rockchip_stimer_init(void)
{
	/* If Timer already enabled, don't re-init it */
	u32 reg = readl(CONFIG_ROCKCHIP_STIMER_BASE + 0x10);
	if ( reg & 0x1 )
		return;
#ifndef CONFIG_ARM64
	asm volatile("mcr p15, 0, %0, c14, c0, 0"
		     : : "r"(COUNTER_FREQUENCY));
#endif
	writel(0, CONFIG_ROCKCHIP_STIMER_BASE + 0x10);
	writel(0xffffffff, CONFIG_ROCKCHIP_STIMER_BASE);
	writel(0xffffffff, CONFIG_ROCKCHIP_STIMER_BASE + 4);
	writel(1, CONFIG_ROCKCHIP_STIMER_BASE + 0x10);
}

__weak int arch_cpu_init(void)
{
	return 0;
}

__weak int rk_board_init_f(void)
{
	return 0;
}

#ifndef CONFIG_SPL_LIBGENERIC_SUPPORT
void udelay(unsigned long usec)
{
	__udelay(usec);
}

void hang(void)
{
	bootstage_error(BOOTSTAGE_ID_NEED_RESET);
	for (;;)
		;
}

/**
 * memset - Fill a region of memory with the given value
 * @s: Pointer to the start of the area.
 * @c: The byte to fill the area with
 * @count: The size of the area.
 *
 * Do not use memset() to access IO space, use memset_io() instead.
 */
void *memset(void *s, int c, size_t count)
{
	unsigned long *sl = (unsigned long *)s;
	char *s8;

#if !CONFIG_IS_ENABLED(TINY_MEMSET)
	unsigned long cl = 0;
	int i;

	/* do it one word at a time (32 bits or 64 bits) while possible */
	if (((ulong)s & (sizeof(*sl) - 1)) == 0) {
		for (i = 0; i < sizeof(*sl); i++) {
			cl <<= 8;
			cl |= c & 0xff;
		}
		while (count >= sizeof(*sl)) {
			*sl++ = cl;
			count -= sizeof(*sl);
		}
	}
#endif /* fill 8 bits at a time */
	s8 = (char *)sl;
	while (count--)
		*s8++ = c;

	return s;
}
#endif

/*
*
* usb current limit : GPIO6_A6 (H:unlock, L:lock)
*
*/
void usb_current_limit_ctrl(bool unlock_current)
{
	int tmp;

	tmp = readl(RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);
	if(unlock_current == true)
		writel(tmp | 0x40, RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);
	else
		writel(tmp & ~0x40, RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);

	tmp = readl(RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);
	writel(tmp | 0x40, RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);
}

void board_init_f(ulong dummy)
{
#ifdef CONFIG_SPL_FRAMEWORK
	int ret;
#if !defined(CONFIG_SUPPORT_TPL)
	struct udevice *dev;
#endif
#endif

	rockchip_stimer_init();
#define EARLY_UART
#if defined(EARLY_UART) && defined(CONFIG_DEBUG_UART)
	/*
	 * Debug UART can be used from here if required:
	 *
	 * debug_uart_init();
	 * printch('a');
	 * printhex8(0x1234);
	 * printascii("string");
	 */
	debug_uart_init();
	printascii("U-Boot SPL board init");
#endif
	usb_current_limit_ctrl(true);

#ifdef CONFIG_SPL_FRAMEWORK
	ret = spl_early_init();
	if (ret) {
		printf("spl_early_init() failed: %d\n", ret);
		hang();
	}
#if !defined(CONFIG_SUPPORT_TPL)
	debug("\nspl:init dram\n");
	ret = uclass_get_device(UCLASS_RAM, 0, &dev);
	if (ret) {
		printf("DRAM init failed: %d\n", ret);
		return;
	}
#endif
	preloader_console_init();
#else
	/* Some SoCs like rk3036 does not use any frame work */
	sdram_init();
#endif

	arch_cpu_init();
	rk_board_init_f();
#if CONFIG_IS_ENABLED(ROCKCHIP_BACK_TO_BROM) && !defined(CONFIG_SPL_BOARD_INIT)
	back_to_bootrom(BROM_BOOT_NEXTSTAGE);
#endif

}

#ifdef CONFIG_SPL_LOAD_FIT
int board_fit_config_name_match(const char *name)
{
	/* Just empty function now - can't decide what to choose */
	debug("%s: %s\n", __func__, name);

	return 0;
}
#endif

#ifdef CONFIG_SPL_BOARD_INIT
__weak int rk_spl_board_init(void)
{
	return 0;
}

static int setup_led(void)
{
#ifdef CONFIG_SPL_LED
	struct udevice *dev;
	char *led_name;
	int ret;

	led_name = fdtdec_get_config_string(gd->fdt_blob, "u-boot,boot-led");
	if (!led_name)
		return 0;
	ret = led_get_by_label(led_name, &dev);
	if (ret) {
		debug("%s: get=%d\n", __func__, ret);
		return ret;
	}
	ret = led_set_on(dev, 1);
	if (ret)
		return ret;
#endif

	return 0;
}

void spl_board_init(void)
{
	int ret;

	ret = setup_led();

	if (ret) {
		debug("LED ret=%d\n", ret);
		hang();
	}

	rk_spl_board_init();
#if CONFIG_IS_ENABLED(ROCKCHIP_BACK_TO_BROM)
	back_to_bootrom(BROM_BOOT_NEXTSTAGE);
#endif
	return;
}
#endif

void spl_perform_fixups(struct spl_image_info *spl_image)
{
#ifdef CONFIG_ROCKCHIP_PRELOADER_ATAGS
	atags_set_bootdev_by_spl_bootdevice(spl_image->boot_device);
#endif
	return;
}

#ifdef CONFIG_SPL_KERNEL_BOOT
static int spl_rockchip_dnl_key_pressed(void)
{
#if defined(CONFIG_SPL_INPUT)
	return key_read(KEY_VOLUMEUP);
#else
	return 0;
#endif
}

void spl_next_stage(struct spl_image_info *spl)
{
	uint32_t reg_boot_mode;

	if (spl_rockchip_dnl_key_pressed()) {
		spl->next_stage = SPL_NEXT_STAGE_UBOOT;
		return;
	}

	reg_boot_mode = readl((void *)CONFIG_ROCKCHIP_BOOT_MODE_REG);
	switch (reg_boot_mode) {
	case BOOT_COLD:
	case BOOT_PANIC:
	case BOOT_WATCHDOG:
	case BOOT_NORMAL:
		spl->next_stage = SPL_NEXT_STAGE_KERNEL;
		break;
	default:
		spl->next_stage = SPL_NEXT_STAGE_UBOOT;
	}
}
#endif

int spl_board_prepare_for_jump(struct spl_image_info *spl_image)
{
#if CONFIG_SPL_FIT_ROLLBACK_PROTECT
	/* TODO */
	printf("spl fit: rollback protect not implement\n");
#endif
	return 0;
}

void spl_hang_reset(void)
{
	printf("# Reset the board to bootrom #\n");
#if defined(CONFIG_SPL_SYSRESET) && defined(CONFIG_SPL_DRIVERS_MISC_SUPPORT)
	writel(BOOT_BROM_DOWNLOAD, CONFIG_ROCKCHIP_BOOT_MODE_REG);
	do_reset(NULL, 0, 0, NULL);
#endif
}

int fit_board_verify_required_sigs(void)
{
	uint8_t vboot = 0;
#if defined(CONFIG_SPL_ROCKCHIP_SECURE_OTP) || defined(CONFIG_SPL_ROCKCHIP_SECURE_OTP_V2)
	struct udevice *dev;

	dev = misc_otp_get_device(OTP_S);
	if (!dev)
		return 1;

	if (misc_otp_read(dev, 0, &vboot, 1)) {
		printf("Can't read verified-boot flag\n");
		return 1;
	}
#endif
	printf("## Verified-boot: %d\n", vboot == 0xff);

	return vboot == 0xff;
}
