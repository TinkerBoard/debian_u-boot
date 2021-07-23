/*
 * (C) Copyright 2016 Fuzhou Rockchip Electronics Co., Ltd
 *
 * Rockchip SD Host Controller Interface
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <asm/arch/hardware.h>
#include <common.h>
#include <dm.h>
#include <dt-structs.h>
#include <linux/libfdt.h>
#include <malloc.h>
#include <mapmem.h>
#include <sdhci.h>
#include <clk.h>
#include <syscon.h>
#include <dm/ofnode.h>
#include <asm/arch/clock.h>

DECLARE_GLOBAL_DATA_PTR;
/* 400KHz is max freq for card ID etc. Use that as min */
#define EMMC_MIN_FREQ	400000
#define KHz	(1000)
#define MHz	(1000 * KHz)

#define PHYCTRL_CALDONE_MASK		0x1
#define PHYCTRL_CALDONE_SHIFT		0x6
#define PHYCTRL_CALDONE_DONE		0x1
#define PHYCTRL_DLLRDY_MASK		0x1
#define PHYCTRL_DLLRDY_SHIFT		0x5
#define PHYCTRL_DLLRDY_DONE		0x1
#define PHYCTRL_FREQSEL_200M            0x0
#define PHYCTRL_FREQSEL_50M             0x1
#define PHYCTRL_FREQSEL_100M            0x2
#define PHYCTRL_FREQSEL_150M            0x3

/* Rockchip specific Registers */
#define DWCMSHC_EMMC_DLL_CTRL		0x800
#define DWCMSHC_EMMC_DLL_RXCLK		0x804
#define DWCMSHC_EMMC_DLL_TXCLK		0x808
#define DWCMSHC_EMMC_DLL_STRBIN		0x80c
#define DWCMSHC_EMMC_DLL_STATUS0	0x840
#define DWCMSHC_EMMC_DLL_STATUS1	0x844
#define DWCMSHC_EMMC_DLL_START		BIT(0)
#define DWCMSHC_EMMC_DLL_RXCLK_SRCSEL	29
#define DWCMSHC_EMMC_DLL_START_POINT	16
#define DWCMSHC_EMMC_DLL_INC		8
#define DWCMSHC_EMMC_DLL_DLYENA		BIT(27)
#define DLL_TXCLK_TAPNUM_DEFAULT	0x10
#define DLL_STRBIN_TAPNUM_DEFAULT	0x3
#define DLL_TXCLK_TAPNUM_FROM_SW	BIT(24)
#define DWCMSHC_EMMC_DLL_LOCKED		BIT(8)
#define DWCMSHC_EMMC_DLL_TIMEOUT	BIT(9)
#define DLL_RXCLK_NO_INVERTER		1
#define DLL_RXCLK_INVERTER		0
#define DWCMSHC_ENHANCED_STROBE		BIT(8)
#define DLL_LOCK_WO_TMOUT(x) \
	((((x) & DWCMSHC_EMMC_DLL_LOCKED) == DWCMSHC_EMMC_DLL_LOCKED) && \
	(((x) & DWCMSHC_EMMC_DLL_TIMEOUT) == 0))
#define ROCKCHIP_MAX_CLKS		3

struct rockchip_sdhc_plat {
#if CONFIG_IS_ENABLED(OF_PLATDATA)
	struct dtd_rockchip_rk3399_sdhci_5_1 dtplat;
#endif
	struct mmc_config cfg;
	struct mmc mmc;
};

struct rockchip_emmc_phy {
	u32 emmcphy_con[7];
	u32 reserved;
	u32 emmcphy_status;
};

struct rockchip_sdhc {
	struct sdhci_host host;
	struct udevice *dev;
	void *base;
	struct rockchip_emmc_phy *phy;
	struct clk emmc_clk;
};

struct sdhci_data {
	int (*emmc_set_clock)(struct sdhci_host *host, unsigned int clock);
	int (*emmc_phy_init)(struct udevice *dev);
	int (*get_phy)(struct udevice *dev);
};

static int rk3399_emmc_phy_init(struct udevice *dev)
{
	return 0;
}

static void rk3399_emmc_phy_power_on(struct rockchip_emmc_phy *phy, u32 clock)
{
	u32 caldone, dllrdy, freqsel;
	uint start;

	writel(RK_CLRSETBITS(7 << 4, 0), &phy->emmcphy_con[6]);
	writel(RK_CLRSETBITS(1 << 11, 1 << 11), &phy->emmcphy_con[0]);
	writel(RK_CLRSETBITS(0xf << 7, 6 << 7), &phy->emmcphy_con[0]);

	/*
	 * According to the user manual, calpad calibration
	 * cycle takes more than 2us without the minimal recommended
	 * value, so we may need a little margin here
	 */
	udelay(3);
	writel(RK_CLRSETBITS(1, 1), &phy->emmcphy_con[6]);

	/*
	 * According to the user manual, it asks driver to
	 * wait 5us for calpad busy trimming. But it seems that
	 * 5us of caldone isn't enough for all cases.
	 */
	udelay(500);
	caldone = readl(&phy->emmcphy_status);
	caldone = (caldone >> PHYCTRL_CALDONE_SHIFT) & PHYCTRL_CALDONE_MASK;
	if (caldone != PHYCTRL_CALDONE_DONE) {
		printf("%s: caldone timeout.\n", __func__);
		return;
	}

	/* Set the frequency of the DLL operation */
	if (clock < 75 * MHz)
		freqsel = PHYCTRL_FREQSEL_50M;
	else if (clock < 125 * MHz)
		freqsel = PHYCTRL_FREQSEL_100M;
	else if (clock < 175 * MHz)
		freqsel = PHYCTRL_FREQSEL_150M;
	else
		freqsel = PHYCTRL_FREQSEL_200M;

	/* Set the frequency of the DLL operation */
	writel(RK_CLRSETBITS(3 << 12, freqsel << 12), &phy->emmcphy_con[0]);
	writel(RK_CLRSETBITS(1 << 1, 1 << 1), &phy->emmcphy_con[6]);

	start = get_timer(0);

	do {
		udelay(1);
		dllrdy = readl(&phy->emmcphy_status);
		dllrdy = (dllrdy >> PHYCTRL_DLLRDY_SHIFT) & PHYCTRL_DLLRDY_MASK;
		if (dllrdy == PHYCTRL_DLLRDY_DONE)
			break;
	} while (get_timer(start) < 50000);

	if (dllrdy != PHYCTRL_DLLRDY_DONE)
		printf("%s: dllrdy timeout.\n", __func__);
}

static void rk3399_emmc_phy_power_off(struct rockchip_emmc_phy *phy)
{
	writel(RK_CLRSETBITS(1, 0), &phy->emmcphy_con[6]);
	writel(RK_CLRSETBITS(1 << 1, 0), &phy->emmcphy_con[6]);
}

static int rk3399_emmc_set_clock(struct sdhci_host *host, unsigned int clock)
{
	unsigned int div, clk = 0, timeout;
	unsigned int input_clk;
	struct rockchip_sdhc *priv =
			container_of(host, struct rockchip_sdhc, host);

	/* Wait max 20 ms */
	timeout = 200;
	while (sdhci_readl(host, SDHCI_PRESENT_STATE) &
			   (SDHCI_CMD_INHIBIT | SDHCI_DATA_INHIBIT)) {
		if (timeout == 0) {
			printf("%s: Timeout to wait cmd & data inhibit\n",
			       __func__);
			return -EBUSY;
		}

		timeout--;
		udelay(100);
	}
	sdhci_writew(host, 0, SDHCI_CLOCK_CONTROL);

	if (clock == 0)
		return 0;

	input_clk = clk_set_rate(&priv->emmc_clk, clock);
	if (IS_ERR_VALUE(input_clk))
		input_clk = host->max_clk;

	if (SDHCI_GET_VERSION(host) >= SDHCI_SPEC_300) {
		/*
		 * Check if the Host Controller supports Programmable Clock
		 * Mode.
		 */
		if (host->clk_mul) {
			for (div = 1; div <= 1024; div++) {
				if ((input_clk / div) <= clock)
					break;
			}

			/*
			 * Set Programmable Clock Mode in the Clock
			 * Control register.
			 */
			clk = SDHCI_PROG_CLOCK_MODE;
			div--;
		} else {
			/* Version 3.00 divisors must be a multiple of 2. */
			if (input_clk <= clock) {
				div = 1;
			} else {
				for (div = 2;
				     div < SDHCI_MAX_DIV_SPEC_300;
				     div += 2) {
					if ((input_clk / div) <= clock)
						break;
				}
			}
			div >>= 1;
		}
	} else {
		/* Version 2.00 divisors must be a power of 2. */
		for (div = 1; div < SDHCI_MAX_DIV_SPEC_200; div *= 2) {
			if ((input_clk / div) <= clock)
				break;
		}
		div >>= 1;
	}

	clk |= (div & SDHCI_DIV_MASK) << SDHCI_DIVIDER_SHIFT;
	clk |= ((div & SDHCI_DIV_HI_MASK) >> SDHCI_DIV_MASK_LEN)
		<< SDHCI_DIVIDER_HI_SHIFT;
	clk |= SDHCI_CLOCK_INT_EN;
	sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);

	/* Wait max 20 ms */
	timeout = 20;
	while (!((clk = sdhci_readw(host, SDHCI_CLOCK_CONTROL))
		& SDHCI_CLOCK_INT_STABLE)) {
		if (timeout == 0) {
			printf("%s: Internal clock never stabilised.\n",
			       __func__);
			return -EBUSY;
		}
		timeout--;
		udelay(1000);
	}
	clk |= SDHCI_CLOCK_CARD_EN;
	sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);
	host->clock = clock;

	return 0;
}

static int rk3399_emmc_get_phy(struct udevice *dev)
{
	struct rockchip_sdhc *priv = dev_get_priv(dev);

#if CONFIG_IS_ENABLED(OF_PLATDATA)
	priv->phy = (struct rockchip_emmc_phy *)0xff77f780;
#else
	ofnode phy_node;
	void *grf_base;
	u32 grf_phy_offset, phandle;

	phandle = dev_read_u32_default(dev, "phys", 0);
	phy_node = ofnode_get_by_phandle(phandle);
	if (!ofnode_valid(phy_node)) {
		debug("Not found emmc phy device\n");
		return -ENODEV;
	}

	grf_base = syscon_get_first_range(ROCKCHIP_SYSCON_GRF);
	if (grf_base < 0)
		printf("%s Get syscon grf failed", __func__);
	grf_phy_offset = ofnode_read_u32_default(phy_node, "reg", 0);

	priv->phy = (struct rockchip_emmc_phy *)(grf_base + grf_phy_offset);
#endif
	return 0;
}

static int rk3399_sdhci_emmc_set_clock(struct sdhci_host *host, unsigned int clock)
{
	struct rockchip_sdhc *priv =
			container_of(host, struct rockchip_sdhc, host);
	int cycle_phy = host->clock != clock &&
			clock > EMMC_MIN_FREQ;

	if (cycle_phy)
		rk3399_emmc_phy_power_off(priv->phy);

	rk3399_emmc_set_clock(host, clock);

	if (cycle_phy)
		rk3399_emmc_phy_power_on(priv->phy, clock);

	return 0;
}

static int rk3568_emmc_phy_init(struct udevice *dev)
{
	struct rockchip_sdhc *prv = dev_get_priv(dev);
	struct sdhci_host *host = &prv->host;
	u32 extra;

	extra = DLL_RXCLK_NO_INVERTER << DWCMSHC_EMMC_DLL_RXCLK_SRCSEL;
	sdhci_writel(host, extra, DWCMSHC_EMMC_DLL_RXCLK);
	return 0;
}

static int rk3568_sdhci_emmc_set_clock(struct sdhci_host *host, unsigned int clock)
{
	u32 extra;
	int timeout = 500, ret;

	ret = rk3399_emmc_set_clock(host, clock);

	if (clock >= 50 * 1000000) {
		sdhci_writel(host, BIT(1), DWCMSHC_EMMC_DLL_CTRL);
		udelay(1);
		sdhci_writel(host, 0, DWCMSHC_EMMC_DLL_CTRL);
		/* Init DLL settings */
		extra = 0x5 << DWCMSHC_EMMC_DLL_START_POINT |
			0x2 << DWCMSHC_EMMC_DLL_INC |
			DWCMSHC_EMMC_DLL_START;
		sdhci_writel(host, extra, DWCMSHC_EMMC_DLL_CTRL);

		while (1) {
			if (timeout < 0)
				return -ETIMEDOUT;
			if (DLL_LOCK_WO_TMOUT((sdhci_readl(host, DWCMSHC_EMMC_DLL_STATUS0))))
				break;
			udelay(1);
			timeout--;
		}

		extra = DWCMSHC_EMMC_DLL_DLYENA |
			DLL_RXCLK_NO_INVERTER << DWCMSHC_EMMC_DLL_RXCLK_SRCSEL;
		sdhci_writel(host, extra, DWCMSHC_EMMC_DLL_RXCLK);

		extra = DWCMSHC_EMMC_DLL_DLYENA |
			DLL_TXCLK_TAPNUM_DEFAULT |
			DLL_TXCLK_TAPNUM_FROM_SW;
		sdhci_writel(host, extra, DWCMSHC_EMMC_DLL_TXCLK);

		extra = DWCMSHC_EMMC_DLL_DLYENA |
			DLL_STRBIN_TAPNUM_DEFAULT;
		sdhci_writel(host, extra, DWCMSHC_EMMC_DLL_STRBIN);
		udelay(1);
	} else {
		/* reset the clock phase when the frequency is lower than 52MHz */
		sdhci_writel(host, 0, DWCMSHC_EMMC_DLL_CTRL);
		extra = DLL_RXCLK_NO_INVERTER << DWCMSHC_EMMC_DLL_RXCLK_SRCSEL;
		sdhci_writel(host, extra, DWCMSHC_EMMC_DLL_RXCLK);
		sdhci_writel(host, 0, DWCMSHC_EMMC_DLL_TXCLK);
		sdhci_writel(host, 0, DWCMSHC_EMMC_DLL_STRBIN);
		udelay(1);
	}

	return ret;
}

static int rk3568_emmc_get_phy(struct udevice *dev)
{
	return 0;
}

static int arasan_sdhci_set_clock(struct sdhci_host *host, unsigned int clock)
{
	struct rockchip_sdhc *priv =
			container_of(host, struct rockchip_sdhc, host);
	struct sdhci_data *data = (struct sdhci_data *)dev_get_driver_data(priv->dev);
	if (!data)
		return -EINVAL;

	return data->emmc_set_clock(host, clock);
}

static struct sdhci_ops arasan_sdhci_ops = {
	.set_clock	= arasan_sdhci_set_clock,
};

static int arasan_sdhci_probe(struct udevice *dev)
{
	struct sdhci_data *data = (struct sdhci_data *)dev_get_driver_data(dev);
	struct mmc_uclass_priv *upriv = dev_get_uclass_priv(dev);
	struct rockchip_sdhc_plat *plat = dev_get_platdata(dev);
	struct rockchip_sdhc *prv = dev_get_priv(dev);
	struct sdhci_host *host = &prv->host;
	int max_frequency, ret;
	struct clk clk;

#if CONFIG_IS_ENABLED(OF_PLATDATA)
	struct dtd_rockchip_rk3399_sdhci_5_1 *dtplat = &plat->dtplat;

	host->name = dev->name;
	host->ioaddr = map_sysmem(dtplat->reg[0], dtplat->reg[1]);
	host->host_caps |= MMC_MODE_8BIT;
	max_frequency = dtplat->max_frequency;
	ret = clk_get_by_index_platdata(dev, 0, dtplat->clocks, &clk);
#else
	max_frequency = dev_read_u32_default(dev, "max-frequency", 0);
	switch (dev_read_u32_default(dev, "bus-width", 4)) {
	case 8:
		host->host_caps |= MMC_MODE_8BIT;
		break;
	case 4:
		host->host_caps |= MMC_MODE_4BIT;
		break;
	case 1:
		break;
	default:
		printf("Invalid \"bus-width\" value\n");
		return -EINVAL;
	}
	ret = clk_get_by_index(dev, 0, &clk);
#endif
	if (!ret) {
		ret = clk_set_rate(&clk, max_frequency);
		if (IS_ERR_VALUE(ret))
			printf("%s clk set rate fail!\n", __func__);
	} else {
		printf("%s fail to get clk\n", __func__);
	}

	prv->emmc_clk = clk;
	prv->dev = dev;
	ret = data->get_phy(dev);
	if (ret)
		return ret;

	ret = data->emmc_phy_init(dev);
	if (ret)
		return ret;

	host->ops = &arasan_sdhci_ops;

	host->quirks = SDHCI_QUIRK_WAIT_SEND_CMD;
	host->max_clk = max_frequency;

	if (dev_read_bool(dev, "mmc-hs200-1_8v"))
		host->host_caps |= MMC_MODE_HS200;
	else if (dev_read_bool(dev, "mmc-hs400-1_8v"))
		host->host_caps |= MMC_MODE_HS400;
	ret = sdhci_setup_cfg(&plat->cfg, host, 0, EMMC_MIN_FREQ);

	host->mmc = &plat->mmc;
	if (ret)
		return ret;
	host->mmc->priv = &prv->host;
	host->mmc->dev = dev;
	upriv->mmc = host->mmc;

	return sdhci_probe(dev);
}

static int arasan_sdhci_ofdata_to_platdata(struct udevice *dev)
{
#if !CONFIG_IS_ENABLED(OF_PLATDATA)
	struct sdhci_host *host = dev_get_priv(dev);

	host->name = dev->name;
	host->ioaddr = dev_read_addr_ptr(dev);
#endif

	return 0;
}

static int rockchip_sdhci_bind(struct udevice *dev)
{
	struct rockchip_sdhc_plat *plat = dev_get_platdata(dev);

	return sdhci_bind(dev, &plat->mmc, &plat->cfg);
}

static const struct sdhci_data arasan_data = {
	.emmc_set_clock = rk3399_sdhci_emmc_set_clock,
	.get_phy = rk3399_emmc_get_phy,
	.emmc_phy_init = rk3399_emmc_phy_init,
};

static const struct sdhci_data snps_data = {
	.emmc_set_clock = rk3568_sdhci_emmc_set_clock,
	.get_phy = rk3568_emmc_get_phy,
	.emmc_phy_init = rk3568_emmc_phy_init,
};

static const struct udevice_id arasan_sdhci_ids[] = {
	{
		.compatible = "arasan,sdhci-5.1",
		.data = (ulong)&arasan_data,
	},
	{
		.compatible = "snps,dwcmshc-sdhci",
		.data = (ulong)&snps_data,
	},
	{ }
};

U_BOOT_DRIVER(arasan_sdhci_drv) = {
	.name		= "rockchip_rk3399_sdhci_5_1",
	.id		= UCLASS_MMC,
	.of_match	= arasan_sdhci_ids,
	.ofdata_to_platdata = arasan_sdhci_ofdata_to_platdata,
	.ops		= &sdhci_ops,
	.bind		= rockchip_sdhci_bind,
	.probe		= arasan_sdhci_probe,
	.priv_auto_alloc_size = sizeof(struct rockchip_sdhc),
	.platdata_auto_alloc_size = sizeof(struct rockchip_sdhc_plat),
};
