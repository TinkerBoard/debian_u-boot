/*
 * (C) Copyright 2015 Google, Inc
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <clk.h>
#include <dm.h>
#include <ram.h>
#include <syscon.h>
#include <asm/io.h>
#include <asm/arch/clock.h>
#include <asm/arch/periph.h>
#include <asm/arch/pmu_rk3288.h>
#include <asm/arch/qos_rk3288.h>
#include <asm/arch/boot_mode.h>
#include <asm/arch/timer.h>
#include <asm/gpio.h>
#include <dm/pinctrl.h>
#include <dt-bindings/clock/rk3288-cru.h>
#include <power/regulator.h>

DECLARE_GLOBAL_DATA_PTR;

#define PMU_BASE	0xff730000

enum project_id {
	TinkerBoardS = 0,
	TinkerBoardS_HV = 1,
	TinkerBoardR_BR = 4,
	TinkerBoard  = 7,
};

enum pcb_id {
	SR,
	ER,
	PR,
};

extern bool force_ums;

static void setup_boot_mode(void)
{
	struct rk3288_pmu *const pmu = (void *)PMU_BASE;
	int boot_mode = readl(&pmu->sys_reg[0]);

	debug("boot mode %x.\n", boot_mode);

	/* Clear boot mode */
	writel(BOOT_NORMAL, &pmu->sys_reg[0]);

	switch (boot_mode) {
	case BOOT_FASTBOOT:
		printf("enter fastboot!\n");
		setenv("preboot", "setenv preboot; fastboot usb0");
		break;
	case BOOT_UMS:
		printf("enter UMS!\n");
		setenv("preboot", "setenv preboot; if mmc dev 0;"
		       "then ums mmc 0; else ums mmc 1;fi");
		break;
	}
}

__weak int rk_board_late_init(void)
{
	return 0;
}

int rk3288_qos_init(void)
{
	int val = 2 << PRIORITY_HIGH_SHIFT | 2 << PRIORITY_LOW_SHIFT;
	/* set vop qos to higher priority */
	writel(val, CPU_AXI_QOS_PRIORITY + VIO0_VOP_QOS);
	writel(val, CPU_AXI_QOS_PRIORITY + VIO1_VOP_QOS);

	if (!fdt_node_check_compatible(gd->fdt_blob, 0,
				       "rockchip,rk3288-tinker"))
	{
		/* set isp qos to higher priority */
		writel(val, CPU_AXI_QOS_PRIORITY + VIO1_ISP_R_QOS);
		writel(val, CPU_AXI_QOS_PRIORITY + VIO1_ISP_W0_QOS);
		writel(val, CPU_AXI_QOS_PRIORITY + VIO1_ISP_W1_QOS);
	}
	return 0;
}

int board_late_init(void)
{
	setup_boot_mode();
	rk3288_qos_init();

	return rk_board_late_init();
}

/*
*
* usb current limit : GPIO6_A6 (H:unlock, L:lock)
*
*/
void usb_current_limit_ctrl(bool unlock_current)
{
	int tmp;

	printf("%s: unlock_current = %d\n", __func__, unlock_current);
	tmp = readl(RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);
	if(unlock_current == true)
		writel(tmp | 0x40, RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);
	else
		writel(tmp & ~0x40, RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);

	tmp = readl(RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);
	writel(tmp | 0x40, RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);
}

/*
*
* eMMC maskrom mode : GPIO6_A7 (H:disable maskrom, L:enable maskrom)
*
*/
void rk3288_maskrom_ctrl(bool enable_emmc)
{
	int tmp;

	printf("%s: enable_emmc = %d\n", __func__, enable_emmc);
	tmp = readl(RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);
	if(enable_emmc == true)
		writel(tmp | 0x80, RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);
	else
		writel(tmp & ~0x80, RKIO_GPIO6_PHYS + GPIO_SWPORT_DR);

	tmp = readl(RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);
	writel(tmp | 0x80, RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);
	mdelay(10);
}

/*
*
* project id        : GPIO2_A3 GPIO2_A2 GPIO2_A1
* pcb id            : GPIO2_B2 GPIO2_B1 GPIO2_B0
* SDP/CDP           : GPIO6_A5 (H:SDP, L:CDP)
* usb current limit : GPIO6_A6 (H:unlock, L:lock)
* eMMC maskrom mode : GPIO6_A7 (H:disable maskrom, L:enable maskrom)
*
* Please check TRM V1.2 part1 page 152 for the following register settings
*
*/
int check_force_enter_ums_mode(void)
{
	int tmp;
	enum pcb_id pcbid;
	enum project_id projectid;

	// GPIO2_A3/GPIO2_A2/GPIO2_A1 pull up enable
	tmp = readl(RKIO_GRF_PHYS + GRF_GPIO2A_P);
	writel((tmp&~(0x03F<<2)) | 0x3F<<(16 + 2) | 0x15<<2, RKIO_GRF_PHYS + GRF_GPIO2A_P);

	// GPIO2_A3/GPIO2_A2/GPIO2_A1/GPIO2_B2/GPIO2_B1/GPIO2_B0 set to input
	tmp = readl(RKIO_GPIO2_PHYS + GPIO_SWPORT_DDR);
	writel(tmp & ~(0x70E), RKIO_GPIO2_PHYS + GPIO_SWPORT_DDR);

	// GPIO6_A5 pull up/down disable
	tmp = readl(RKIO_GRF_PHYS + GRF_GPIO6A_P);
	writel((tmp&~(0x03<<10)) | 0x03<<(16 + 10), RKIO_GRF_PHYS + GRF_GPIO6A_P);

	// GPIO6_A5 set to input
	tmp = readl(RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);
	writel(tmp & ~(0x20), RKIO_GPIO6_PHYS + GPIO_SWPORT_DDR);

	mdelay(10);

	// read GPIO2_A3/GPIO2_A2/GPIO2_A1 value
	projectid = (readl(RKIO_GPIO2_PHYS + GPIO_EXT_PORT) & 0x0E) >>1;

	// read GPIO2_B2/GPIO2_B1/GPIO2_B0 value
	pcbid = (readl(RKIO_GPIO2_PHYS + GPIO_EXT_PORT) & 0x700) >> 8;

	// only TinkerBoard S PR stage PCB & TinkerBoard S/HV has this function
	if(((projectid == TinkerBoardS) && (pcbid >= ER))
	   || (projectid == TinkerBoardS_HV)){
		printf("PC event = 0x%x\n", readl(RKIO_GPIO6_PHYS + GPIO_EXT_PORT)&0x20);
		if((readl(RKIO_GPIO6_PHYS + GPIO_EXT_PORT)&0x20)==0x20) {
			// SDP detected, enable EMMC and unlock usb current limit
			printf("usb connected to SDP, force enter ums mode\n");
			force_ums = true;
			rk3288_maskrom_ctrl(true);
			usb_current_limit_ctrl(true);
		} else {
			usb_current_limit_ctrl(false);
		}
	}
	return 0;
}

#ifndef CONFIG_ROCKCHIP_SPL_BACK_TO_BROM
static int veyron_init(void)
{
	struct udevice *dev;
	struct clk clk;
	int ret;

	ret = regulator_get_by_platname("vdd_arm", &dev);
	if (ret) {
		debug("Cannot set regulator name\n");
		return ret;
	}

	/* Slowly raise to max CPU voltage to prevent overshoot */
	ret = regulator_set_value(dev, 1200000);
	if (ret)
		return ret;
	udelay(175); /* Must wait for voltage to stabilize, 2mV/us */
	ret = regulator_set_value(dev, 1400000);
	if (ret)
		return ret;
	udelay(100); /* Must wait for voltage to stabilize, 2mV/us */

	ret = rockchip_get_clk(&clk.dev);
	if (ret)
		return ret;
	clk.id = PLL_APLL;
	ret = clk_set_rate(&clk, 1800000000);
	if (IS_ERR_VALUE(ret))
		return ret;

	return 0;
}
#endif

int board_init(void)
{
#ifdef CONFIG_ROCKCHIP_SPL_BACK_TO_BROM
	struct udevice *pinctrl;
	int ret;

	rockchip_timer_init();

	/*
	 * We need to implement sdcard iomux here for the further
	 * initlization, otherwise, it'll hit sdcard command sending
	 * timeout exception.
	 */
	ret = uclass_get_device(UCLASS_PINCTRL, 0, &pinctrl);
	if (ret) {
		debug("%s: Cannot find pinctrl device\n", __func__);
		goto err;
	}
	ret = pinctrl_request_noflags(pinctrl, PERIPH_ID_SDCARD);
	if (ret) {
		debug("%s: Failed to set up SD card\n", __func__);
		goto err;
	}

	return 0;
err:
	printf("board_init: Error %d\n", ret);

	/* No way to report error here */
	hang();

	return -1;
#else
	int ret;

	/* We do some SoC one time setting here */
	if (!fdt_node_check_compatible(gd->fdt_blob, 0, "google,veyron")) {
		ret = veyron_init();
		if (ret)
			return ret;
	}

	return 0;
#endif
}

#ifndef CONFIG_SYS_DCACHE_OFF
void enable_caches(void)
{
	/* Enable D-cache. I-cache is already enabled in start.S */
	dcache_enable();
}
#endif

#if defined(CONFIG_USB_GADGET) && defined(CONFIG_USB_GADGET_DWC2_OTG)
#include <usb.h>
#include <usb/dwc2_udc.h>

static struct dwc2_plat_otg_data rk3288_otg_data = {
	.rx_fifo_sz	= 512,
	.np_tx_fifo_sz	= 16,
	.tx_fifo_sz	= 128,
};

int board_usb_init(int index, enum usb_init_type init)
{
	int node, phy_node;
	const char *mode;
	bool matched = false;
	const void *blob = gd->fdt_blob;
	u32 grf_phy_offset;

	/* find the usb_otg node */
	node = fdt_node_offset_by_compatible(blob, -1,
					"rockchip,rk3288-usb");

	while (node > 0) {
		mode = fdt_getprop(blob, node, "dr_mode", NULL);
		if (mode && strcmp(mode, "otg") == 0) {
			matched = true;
			break;
		}

		node = fdt_node_offset_by_compatible(blob, node,
					"rockchip,rk3288-usb");
	}
	if (!matched) {
		debug("Not found usb_otg device\n");
		return -ENODEV;
	}
	rk3288_otg_data.regs_otg = fdtdec_get_addr(blob, node, "reg");

	node = fdtdec_lookup_phandle(blob, node, "phys");
	if (node <= 0) {
		debug("Not found usb phy device\n");
		return -ENODEV;
	}

	phy_node = fdt_parent_offset(blob, node);
	if (phy_node <= 0) {
		debug("Not found usb phy device\n");
		return -ENODEV;
	}

	rk3288_otg_data.phy_of_node = phy_node;
	grf_phy_offset = fdtdec_get_addr(blob, node, "reg");

	/* find the grf node */
	node = fdt_node_offset_by_compatible(blob, -1,
					"rockchip,rk3288-grf");
	if (node <= 0) {
		debug("Not found grf device\n");
		return -ENODEV;
	}
	rk3288_otg_data.regs_phy = grf_phy_offset +
				fdtdec_get_addr(blob, node, "reg");

	return dwc2_udc_probe(&rk3288_otg_data);
}

int board_usb_cleanup(int index, enum usb_init_type init)
{
	return 0;
}
#endif

static int do_clock(cmd_tbl_t *cmdtp, int flag, int argc,
		       char * const argv[])
{
	static const struct {
		char *name;
		int id;
	} clks[] = {
		{ "osc", CLK_OSC },
		{ "apll", CLK_ARM },
		{ "dpll", CLK_DDR },
		{ "cpll", CLK_CODEC },
		{ "gpll", CLK_GENERAL },
#ifdef CONFIG_ROCKCHIP_RK3036
		{ "mpll", CLK_NEW },
#else
		{ "npll", CLK_NEW },
#endif
	};
	int ret, i;
	struct udevice *dev;

	ret = rockchip_get_clk(&dev);
	if (ret) {
		printf("clk-uclass not found\n");
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(clks); i++) {
		struct clk clk;
		ulong rate;

		clk.id = clks[i].id;
		ret = clk_request(dev, &clk);
		if (ret < 0)
			continue;

		rate = clk_get_rate(&clk);
		printf("%s: %lu\n", clks[i].name, rate);

		clk_free(&clk);
	}

	return 0;
}

U_BOOT_CMD(
	clock, 2, 1, do_clock,
	"display information about clocks",
	""
);

#define GRF_SOC_CON2 0xff77024c

int board_early_init_f(void)
{
	struct udevice *pinctrl;
	struct udevice *dev;
	int ret;

	/*
	 * This init is done in SPL, but when chain-loading U-Boot SPL will
	 * have been skipped. Allow the clock driver to check if it needs
	 * setting up.
	 */
	ret = rockchip_get_clk(&dev);
	if (ret) {
		debug("CLK init failed: %d\n", ret);
		return ret;
	}
	ret = uclass_get_device(UCLASS_PINCTRL, 0, &pinctrl);
	if (ret) {
		debug("%s: Cannot find pinctrl device\n", __func__);
		return ret;
	}

	/* Enable debug UART */
	ret = pinctrl_request_noflags(pinctrl, PERIPH_ID_UART_DBG);
	if (ret) {
		debug("%s: Failed to set up console UART\n", __func__);
		return ret;
	}
	rk_setreg(GRF_SOC_CON2, 1 << 0);

	return 0;
}
