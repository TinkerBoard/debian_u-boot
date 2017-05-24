/*
 * (C) Copyright 2016 Rockchip Electronics Co., Ltd
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <power/regulator.h>

#ifdef CONFIG_DM_PMIC
static int rockchip_set_regulator_on(const char *name, uint uv)
{
	struct udevice *dev;
	int ret;

	ret = regulator_get_by_platname(name, &dev);
	if (ret) {
		debug("%s: Cannot find regulator %s\n", __func__, name);
		return ret;
	}
	ret = regulator_set_value(dev, uv);
	if (ret) {
		debug("%s: Cannot set regulator %s\n", __func__, name);
		return ret;
	}
	ret = regulator_set_enable(dev, 1);
	if (ret) {
		debug("%s: Cannot enable regulator %s\n", __func__, name);
		return ret;
	}

	return 0;
}

int power_init_board(void)
{
	int ret = rockchip_set_regulator_on("vcc33_mipi", 3300000);
	if (ret)
		return ret;

	return 0;
}
#endif
