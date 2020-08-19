/*
 * Copyright (c) 2011 Sebastian Andrzej Siewior <bigeasy@linutronix.de>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <image.h>
#include <android_image.h>
#include <android_bootloader.h>
#include <malloc.h>
#include <mapmem.h>
#include <errno.h>
#include <boot_rkimg.h>
#include <crypto.h>
#include <sysmem.h>
#include <u-boot/sha1.h>
#ifdef CONFIG_RKIMG_BOOTLOADER
#include <asm/arch/resource_img.h>
#endif
#ifdef CONFIG_RK_AVB_LIBAVB_USER
#include <android_avb/avb_slot_verify.h>
#include <android_avb/avb_ops_user.h>
#include <android_avb/rk_avb_ops_user.h>
#endif
#include <optee_include/OpteeClientInterface.h>

DECLARE_GLOBAL_DATA_PTR;

#define ANDROID_IMAGE_DEFAULT_KERNEL_ADDR	0x10008000
#define ANDROID_ARG_FDT_FILENAME "rk-kernel.dtb"
#define ANDROID_Q_VER				10

/* Defined by rockchip legacy mkboot tool(SDK version < 8.1) */
#define ANDROID_ROCKCHIP_LEGACY_PAGE_SIZE	0x4000

#define MAX_OVERLAY_NAME_LENGTH 128

struct hw_config
{
	int valid;

	int fiq_debugger;
	int i2c1, i2c4;
	int spi0, spi2;
	int pwm2, pwm3;
	int pcm, pcm_i2s;
	int uart1, uart2, uart3, uart4;

	int overlay_count;
	char **overlay_file;
};

static unsigned long hw_skip_comment(char *text)
{
	int i = 0;
	if (*text == '#') {
		while (*(text + i) != 0x00) {
			if (*(text + (i++)) == 0x0a)
				break;
		}
	}
	return i;
}

static unsigned long hw_skip_line(char *text)
{
	if (*text == 0x0a)
		return 1;
	else
		return 0;
}

static unsigned long get_intf_value(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if (memcmp(text, "fiq_debugger=",  13) == 0) {
		i = 13;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->fiq_debugger = 1;
			hw_conf->uart1 = -1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->fiq_debugger = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "i2c1=", 5) == 0) {
		i = 5;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->i2c1 = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->i2c1 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "i2c4=",  5) == 0) {
		i = 5;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->i2c4 = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->i2c4 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "spi0=", 5) == 0) {
		i = 5;
		if (memcmp(text + i, "on", 2) == 0) {
			if (hw_conf->spi0 != -1)
				hw_conf->spi0 = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->spi0 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "spi2=", 5) == 0) {
		i = 5;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->spi2 = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->spi2 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "pwm2=", 5) == 0) {
		i = 5;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->pwm2 = 1;
			hw_conf->uart2 = -1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->pwm2 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "pwm3=", 5) == 0) {
		i = 5;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->pwm3 = 1;
			hw_conf->uart2 = -1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->pwm3 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "pcm=", 4) == 0) {
		i = 4;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->pcm = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->pcm = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "pcm_i2s=", 8) == 0) {
		i = 8;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->pcm_i2s = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->pcm_i2s = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "uart1=", 6) == 0) {
		i = 6;
		if (memcmp(text + i, "on", 2) == 0) {
			if (hw_conf->fiq_debugger != 1)
				hw_conf->uart1 = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->uart1 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "uart2=", 6) == 0) {
		i = 6;
		if (memcmp(text + i, "on", 2) == 0) {
			if (hw_conf->uart2 != -1)
				hw_conf->uart2 = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->uart2 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "uart3=", 6) == 0) {
		i = 6;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->uart3 = 1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->uart3 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else if (memcmp(text, "uart4=", 6) == 0) {
		i = 6;
		if (memcmp(text + i, "on", 2) == 0) {
			hw_conf->uart4 = 1;
			hw_conf->spi0 = -1;
			i = i + 2;
		} else if (memcmp(text + i, "off", 3) == 0) {
			hw_conf->uart4 = -1;
			i = i + 3;
		} else
			goto invalid_line;
	} else
		goto invalid_line;

	while (*(text + i) != 0x00) {
		if (*(text + (i++)) == 0x0a)
			break;
	}
	return i;

invalid_line:
	//It's not a legal line, skip it.
	//printf("get_value: illegal line\n");
	while (*(text + i) != 0x00) {
		if (*(text + (i++)) == 0x0a)
			break;
	}
	return i;
}

static int set_file_conf(char *text, struct hw_config *hw_conf, int start_point, int file_ptr)
{
	char *ptr;
	int name_length;

	name_length = file_ptr - start_point;

	if (name_length && name_length < MAX_OVERLAY_NAME_LENGTH) {
		ptr = (char*)calloc(MAX_OVERLAY_NAME_LENGTH, sizeof(char));
		memcpy(ptr, text + start_point, name_length);
		ptr[name_length] = 0x00;
		hw_conf->overlay_file[hw_conf->overlay_count] = ptr;
		hw_conf->overlay_count += 1;
	}
	//Pass a space for next string.
	start_point = file_ptr + 1;

	return start_point;
}

void count_overlay(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	int start_point = 0;
	int overlay_count = 0;
	int name_length;

	while (*(text + i) != 0x00) {
		if (*(text + i) == 0x20 || *(text + i) == 0x0a) {
			name_length = i - start_point;
			if (name_length && name_length < MAX_OVERLAY_NAME_LENGTH)
				overlay_count += 1;
		}

		if (*(text + i) == 0x20)
			start_point = i + 1;
		else if (*(text + i) == 0x0a)
			break;
		i++;
	}

	hw_conf->overlay_file = (char**)calloc(overlay_count, sizeof(char*));
}

static unsigned long get_overlay(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	int start_point = 0;

	hw_conf->overlay_count = 0;
	while (*(text + i) != 0x00) {
		if (*(text + i) == 0x20 || *(text + i) == 0x0a)
			start_point = set_file_conf(text, hw_conf, start_point, i);

		if (*(text + i) == 0x0a) {
			i++;
			break;
		} else
			i++;
	}

	return i;
}

static unsigned long hw_parse_property(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if (memcmp(text, "intf:", 5) == 0) {
		i = 5;
		i = i + get_intf_value(text + i, hw_conf);
	} else if(memcmp(text, "overlay=", 8) == 0) {
		i = 8;
		count_overlay(text + i, hw_conf);
		i = i + get_overlay(text + i, hw_conf);
	} else {
		printf("[conf] hw_parse_property: illegal line\n");
		//It's not a legal line, skip it.
		while (*(text + i) != 0x00) {
			if (*(text + (i++)) == 0x0a)
				break;
		}
	}
	return i;
}

static void parse_hw_config(struct hw_config *hw_conf)
{
	unsigned long count, offset = 0, addr, size;
	char *file_addr, *devnum;
	static char *fs_argv[5];

	int valid = 0;

	devnum = env_get("devnum");
	if (!devnum) {
		printf("Can't get devnum\n");
		goto end;
	}

	file_addr = env_get("conf_addr");
	if (!file_addr) {
		printf("Can't get conf_addr address\n");
		goto end;
	}

	addr = simple_strtoul(file_addr, NULL, 16);
	if (!addr)
		printf("Can't set addr\n");

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";

	if (!strcmp(devnum, "0"))
		fs_argv[2] = "0:7";
	else if (!strcmp(devnum, "1"))
		fs_argv[2] = "1:7";
	else {
		printf("Invalid devnum\n");
		goto end;
	}

	fs_argv[3] = file_addr;
	fs_argv[4] = "config.txt";

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[conf] do_ext2load fail\n");
		goto end;
	}

	size = env_get_ulong("filesize", 16, 0);
	if (!size) {
		printf("[conf] Can't get filesize\n");
		goto end;
	}

	valid = 1;
	printf("config.txt size = %lu\n", size);

	*((char *)file_addr + size) = 0x00;

	while (offset != size) {
		count = hw_skip_comment((char *)(addr + offset));
		if (count > 0) {
			offset = offset + count;
			continue;
		}
		count = hw_skip_line((char *)(addr + offset));
		if (count > 0) {
			offset = offset + count;
			continue;
		}
		count = hw_parse_property((char *)(addr + offset), hw_conf);
		if (count > 0) {
			offset = offset + count;
			continue;
		}
	}
end:
	hw_conf->valid = valid;
}

static int set_hw_property(struct fdt_header *working_fdt, char *path, char *property, char *value, int length)
{
	int offset;
	int ret;

	printf("set_hw_property: %s %s %s\n", path, property, value);
	offset = fdt_path_offset (working_fdt, path);
	if (offset < 0) {
		printf("libfdt fdt_path_offset() returned %s\n", fdt_strerror(offset));
		return -1;
	}
	ret = fdt_setprop(working_fdt, offset, property, value, length);
	if (ret < 0) {
		printf("libfdt fdt_setprop(): %s\n", fdt_strerror(ret));
		return -1;
	}

	return 0;
}

static int flash_gpio(struct fdt_header *working_fdt, char *path, char *property)
{
	int offset, len;;
	const fdt32_t *cell;

	int pin22[3] = {7, 22, 0};
	int pin23[3] = {7, 23, 0};
	int backlight[4] = {7, 2, 0, 166};

	printf("flash_gpio: %s %s\n", path, property);

	offset = fdt_path_offset (working_fdt, path);
	if (offset < 0) {
		printf("libfdt fdt_path_offset() returned %s\n", fdt_strerror(offset));
		return -1;
	}

	cell = fdt_getprop(working_fdt, offset, property, &len);
	if (!cell) {
		printf("libfdt fdt_getprop() fail\n");
		return -1;
	} else {
		int i, j;
		uint32_t adj_val;
		int get_pin22, get_pin23;

		for (i = 0; i < len; i++) {
			get_pin22 = 1;
			get_pin23 = 1;

			for (j = 0; j < 3; j++) {
				if (fdt32_to_cpu(cell[i + j]) != pin22[j])
					get_pin22 = 0;
				if (fdt32_to_cpu(cell[i + j]) != pin23[j])
					get_pin23 = 0;
			}

			if (get_pin22 || get_pin23) {
				for (j = 0; j < 4; j++) {
					adj_val = backlight[j];
					adj_val = cpu_to_fdt32(adj_val);
					fdt_setprop_inplace_namelen_partial(working_fdt, offset, property, strlen(property), (i+j)*4, &adj_val, sizeof(adj_val));
				}
                        }
		}
	}

	return 0;
}

static struct fdt_header *resize_working_fdt(void)
{
	struct fdt_header *working_fdt;
	unsigned long file_addr;
	int err;

	file_addr = env_get_ulong("fdt_addr_r", 16, 0);
	if (!file_addr) {
		printf("Can't get fdt address\n");
		return NULL;
	}

	working_fdt = map_sysmem(file_addr, 0);
	err = fdt_open_into(working_fdt, working_fdt, (1024 * 1024));
	if (err != 0) {
		printf("libfdt fdt_open_into(): %s\n", fdt_strerror(err));
		return NULL;
	}

	printf("fdt magic number %x\n", working_fdt->magic);
	printf("fdt size %u\n", fdt_totalsize(working_fdt));

	return working_fdt;
}

#ifdef CONFIG_OF_LIBFDT_OVERLAY
static int fdt_valid(struct fdt_header **blobp)
{
	const void *blob = *blobp;
	int err;

	if (blob == NULL) {
		printf ("The address of the fdt is invalid (NULL).\n");
		return 0;
	}

	err = fdt_check_header(blob);
	if (err == 0)
		return 1;	/* valid */

	if (err < 0) {
		printf("libfdt fdt_check_header(): %s", fdt_strerror(err));
		/*
		 * Be more informative on bad version.
		 */
		if (err == -FDT_ERR_BADVERSION) {
			if (fdt_version(blob) < FDT_FIRST_SUPPORTED_VERSION) {
				printf (" - too old, fdt %d < %d", fdt_version(blob), FDT_FIRST_SUPPORTED_VERSION);
			}
			if (fdt_last_comp_version(blob) > FDT_LAST_SUPPORTED_VERSION) {
				printf (" - too new, fdt %d > %d", fdt_version(blob), FDT_LAST_SUPPORTED_VERSION);
			}
		}
		printf("\n");
		*blobp = NULL;
		return 0;
	}
	return 1;
}

static int merge_dts_overlay(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, char *overlay_name)
{
	unsigned long addr;
	char *file_addr, *devnum;
	struct fdt_header *blob;
	int ret;
	char overlay_file[] = "overlays/";

	static char *fs_argv[5];

	devnum = env_get("devnum");
	if (!devnum) {
		printf("Can't get devnum\n");
		goto fail;
	}

	file_addr = env_get("fdt_overlay_addr");
	if (!file_addr) {
		printf("Can't get fdt overlay address\n");
		goto fail;
	}

	addr = simple_strtoul(file_addr, NULL, 16);

	strcat(overlay_file, overlay_name);
	strncat(overlay_file, ".dtbo", 6);

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";

	if (!strcmp(devnum, "0"))
		fs_argv[2] = "0:7";
	else if (!strcmp(devnum, "1"))
		fs_argv[2] = "1:7";
	else {
		printf("Invalid devnum\n");
		goto fail;
	}

	fs_argv[3] = file_addr;
	fs_argv[4] = overlay_file;

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[merge_dts_overlay] do_ext2load fail\n");
		goto fail;
	}

	blob = map_sysmem(addr, 0);
	if (!fdt_valid(&blob)) {
		printf("[merge_dts_overlay] fdt_valid is invalid\n");
		goto fail;
	} else
		printf("fdt_valid\n");

	ret = fdt_overlay_apply(working_fdt, blob);
	if (ret) {
		printf("[merge_dts_overlay] fdt_overlay_apply(): %s\n", fdt_strerror(ret));
		goto fail;
	}

	return 0;

fail:
	return -1;
}
#endif

static void handle_hw_conf(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, struct hw_config *hw_conf)
{
	if (working_fdt == NULL)
		return;

#ifdef CONFIG_OF_LIBFDT_OVERLAY
	int i;
	for (i = 0; i < hw_conf->overlay_count; i++) {
		if (merge_dts_overlay(cmdtp, working_fdt, hw_conf->overlay_file[i]) < 0)
			printf("Can't merge dts overlay: %s\n", hw_conf->overlay_file[i]);
		else
			printf("Merged dts overlay: %s\n", hw_conf->overlay_file[i]);

		free(hw_conf->overlay_file[i]);
	}
	free(hw_conf->overlay_file);
#endif

	if (hw_conf->fiq_debugger == 1)
		set_hw_property(working_fdt, "/fiq-debugger", "status", "okay", 5);
	else if (hw_conf->fiq_debugger == -1)
		set_hw_property(working_fdt, "/fiq-debugger", "status", "disabled", 9);

	if (hw_conf->i2c1 == 1)
		set_hw_property(working_fdt, "/i2c@ff140000", "status", "okay", 5);
	else if (hw_conf->i2c1 == -1)
		set_hw_property(working_fdt, "/i2c@ff140000", "status", "disabled", 9);

	if (hw_conf->i2c4 == 1)
		set_hw_property(working_fdt, "/i2c@ff160000", "status", "okay", 5);
	else if (hw_conf->i2c4 == -1)
		set_hw_property(working_fdt, "/i2c@ff160000", "status", "disabled", 9);

	if (hw_conf->spi0 == 1)
		set_hw_property(working_fdt, "/spi@ff110000", "status", "okay", 5);
	else if (hw_conf->spi0 == -1)
		set_hw_property(working_fdt, "/spi@ff110000", "status", "disabled", 9);

	if (hw_conf->spi2 == 1)
		set_hw_property(working_fdt, "/spi@ff130000", "status", "okay", 5);
	else if (hw_conf->spi2 == -1)
		set_hw_property(working_fdt, "/spi@ff130000", "status", "disabled", 9);

	if (hw_conf->pwm2 == 1)
		set_hw_property(working_fdt, "/pwm@ff680020", "status", "okay", 5);
	else if (hw_conf->pwm2 == -1)
		set_hw_property(working_fdt, "/pwm@ff680020", "status", "disabled", 9);

	if (hw_conf->pwm3 == 1)
		set_hw_property(working_fdt, "/pwm@ff680030", "status", "okay", 5);
	else if (hw_conf->pwm3 == -1)
		set_hw_property(working_fdt, "/pwm@ff680030", "status", "disabled", 9);

	if (hw_conf->uart1 == 1)
		set_hw_property(working_fdt, "/serial@ff190000", "status", "okay", 5);
	else if (hw_conf->uart1 == -1)
		set_hw_property(working_fdt, "/serial@ff190000", "status", "disabled", 9);

	if (hw_conf->uart2 == 1) {
		set_hw_property(working_fdt, "/serial@ff690000", "status", "okay", 5);
		flash_gpio(working_fdt, "/pinctrl/gpio_init_config/gpio-init", "rockchip,pins");
	} else if (hw_conf->uart2 == -1)
		set_hw_property(working_fdt, "/serial@ff690000", "status", "disabled", 9);

	if (hw_conf->uart3 == 1)
		set_hw_property(working_fdt, "/serial@ff1b0000", "status", "okay", 5);
	else if (hw_conf->uart3 == -1)
		set_hw_property(working_fdt, "/serial@ff1b0000", "status", "disabled", 9);

	if (hw_conf->uart4 == 1)
		set_hw_property(working_fdt, "/serial@ff1c0000", "status", "okay", 5);
	else if (hw_conf->uart4 == -1)
		set_hw_property(working_fdt, "/serial@ff1c0000", "status", "disabled", 9);

	if (hw_conf->pcm_i2s == 1)
		set_hw_property(working_fdt, "/i2s@ff890000", "status", "okay", 5);
	else if (hw_conf->pcm_i2s == -1)
		set_hw_property(working_fdt, "/i2s@ff890000", "status", "disabled", 9);
}

static char andr_tmp_str[ANDR_BOOT_ARGS_SIZE + 1];
static u32 android_kernel_comp_type = IH_COMP_NONE;

u32 android_image_major_version(void)
{
	/* MSB 7-bits */
	return gd->bd->bi_andr_version >> 25;
}

u32 android_bcb_msg_sector_offset(void)
{
	/*
	 * Rockchip platforms defines BCB message at the 16KB offset of
	 * misc partition while the Google defines it at 0x0 offset.
	 *
	 * From Android-Q, the 0x0 offset is mandary on Google VTS, so that
	 * this is a compatibility according to android image 'os_version'.
	 */
#ifdef CONFIG_RKIMG_BOOTLOADER
	return (android_image_major_version() >= ANDROID_Q_VER) ? 0x0 : 0x20;
#else
	return 0x0;
#endif
}

static ulong android_image_get_kernel_addr(const struct andr_img_hdr *hdr)
{
	/*
	 * All the Android tools that generate a boot.img use this
	 * address as the default.
	 *
	 * Even though it doesn't really make a lot of sense, and it
	 * might be valid on some platforms, we treat that address as
	 * the default value for this field, and try to execute the
	 * kernel in place in such a case.
	 *
	 * Otherwise, we will return the actual value set by the user.
	 */
	if (hdr->kernel_addr == ANDROID_IMAGE_DEFAULT_KERNEL_ADDR)
		return (ulong)hdr + hdr->page_size;

#ifdef CONFIG_ARCH_ROCKCHIP
	/*
	 * If kernel is compressed, kernel_addr is set as decompressed address
	 * after compressed being loaded to ram, so let's use it.
	 */
	if (android_kernel_comp_type != IH_COMP_NONE &&
	    android_kernel_comp_type != IH_COMP_ZIMAGE)
		return hdr->kernel_addr;

	/*
	 * Compatble with rockchip legacy packing with kernel/ramdisk/second
	 * address base from 0x60000000(SDK versiont < 8.1), these are invalid
	 * address, so we calc it by real size.
	 */
	return (ulong)hdr + hdr->page_size;
#else
	return hdr->kernel_addr;
#endif

}

void android_image_set_comp(struct andr_img_hdr *hdr, u32 comp)
{
	android_kernel_comp_type = comp;
}

u32 android_image_get_comp(const struct andr_img_hdr *hdr)
{
	return android_kernel_comp_type;
}

int android_image_parse_kernel_comp(const struct andr_img_hdr *hdr)
{
	ulong kaddr = android_image_get_kernel_addr(hdr);
	return bootm_parse_comp((const unsigned char *)kaddr);
}

/**
 * android_image_get_kernel() - processes kernel part of Android boot images
 * @hdr:	Pointer to image header, which is at the start
 *			of the image.
 * @verify:	Checksum verification flag. Currently unimplemented.
 * @os_data:	Pointer to a ulong variable, will hold os data start
 *			address.
 * @os_len:	Pointer to a ulong variable, will hold os data length.
 *
 * This function returns the os image's start address and length. Also,
 * it appends the kernel command line to the bootargs env variable.
 *
 * Return: Zero, os start address and length on success,
 *		otherwise on failure.
 */
int android_image_get_kernel(const struct andr_img_hdr *hdr, int verify,
			     ulong *os_data, ulong *os_len)
{
	u32 kernel_addr = android_image_get_kernel_addr(hdr);

	/*
	 * Not all Android tools use the id field for signing the image with
	 * sha1 (or anything) so we don't check it. It is not obvious that the
	 * string is null terminated so we take care of this.
	 */
	strncpy(andr_tmp_str, hdr->name, ANDR_BOOT_NAME_SIZE);
	andr_tmp_str[ANDR_BOOT_NAME_SIZE] = '\0';
	if (strlen(andr_tmp_str))
		printf("Android's image name: %s\n", andr_tmp_str);

	printf("Kernel load addr 0x%08x size %u KiB\n",
	       kernel_addr, DIV_ROUND_UP(hdr->kernel_size, 1024));

	int len = 0;
	if (*hdr->cmdline) {
		debug("Kernel command line: %s\n", hdr->cmdline);
		len += strlen(hdr->cmdline);
	}

	char *rootmmc0 = "root=/dev/mmcblk0p8"; /* SDcard Boot */
	char *rootmmc1 = "root=/dev/mmcblk1p8"; /* eMMC Boot */
	len += strlen(rootmmc0);

	char *bootargs = env_get("bootargs");
	if (bootargs)
		len += strlen(bootargs);

	char *newbootargs = malloc(len + 2);
	if (!newbootargs) {
		puts("Error: malloc in android_image_get_kernel failed!\n");
		return -ENOMEM;
	}
	*newbootargs = '\0';

	if (bootargs) {
		strcpy(newbootargs, bootargs);
		strcat(newbootargs, " ");
	}
	if (*hdr->cmdline)
		strcat(newbootargs, hdr->cmdline);

	char *devnum = env_get("devnum");
	if (!strcmp(devnum, "0"))
		strcat(newbootargs, rootmmc1);
	else if (!strcmp(devnum, "1"))
		strcat(newbootargs, rootmmc0);

	env_set("bootargs", newbootargs);

	if (os_data) {
		*os_data = (ulong)hdr;
		*os_data += hdr->page_size;
	}
	if (os_len)
		*os_len = hdr->kernel_size;
	return 0;
}

int android_image_check_header(const struct andr_img_hdr *hdr)
{
	return memcmp(ANDR_BOOT_MAGIC, hdr->magic, ANDR_BOOT_MAGIC_SIZE);
}

ulong android_image_get_end(const struct andr_img_hdr *hdr)
{
	ulong end;
	/*
	 * The header takes a full page, the remaining components are aligned
	 * on page boundary
	 */
	end = (ulong)hdr;
	end += hdr->page_size;
	end += ALIGN(hdr->kernel_size, hdr->page_size);
	end += ALIGN(hdr->ramdisk_size, hdr->page_size);
	end += ALIGN(hdr->second_size, hdr->page_size);

	if (hdr->header_version >= 2) {
		end += ALIGN(hdr->recovery_dtbo_size, hdr->page_size);
		end += ALIGN(hdr->dtb_size, hdr->page_size);
	} else if (hdr->header_version >= 1) {
		end += ALIGN(hdr->recovery_dtbo_size, hdr->page_size);
	}

	return end;
}

u32 android_image_get_ksize(const struct andr_img_hdr *hdr)
{
	return hdr->kernel_size;
}

void android_image_set_kload(struct andr_img_hdr *hdr, u32 load_address)
{
	hdr->kernel_addr = load_address;
}

ulong android_image_get_kload(const struct andr_img_hdr *hdr)
{
	return android_image_get_kernel_addr(hdr);
}

int android_image_get_ramdisk(const struct andr_img_hdr *hdr,
			      ulong *rd_data, ulong *rd_len)
{
	ulong ramdisk_addr_r;

	if (!hdr->ramdisk_size) {
		*rd_data = *rd_len = 0;
		return -1;
	}

	/* Have been loaded by android_image_load_separate() on ramdisk_addr_r */
	ramdisk_addr_r = env_get_ulong("ramdisk_addr_r", 16, 0);
	if (!ramdisk_addr_r) {
		printf("No Found Ramdisk Load Address.\n");
		return -1;
	}

	*rd_data = ramdisk_addr_r;
	*rd_len = hdr->ramdisk_size;

	printf("RAM disk load addr 0x%08lx size %u KiB\n",
	       *rd_data, DIV_ROUND_UP(hdr->ramdisk_size, 1024));

	return 0;
}

int android_image_get_fdt(const struct andr_img_hdr *hdr,
			      ulong *rd_data)
{
	ulong fdt_addr_r;

	if (!hdr->second_size) {
		*rd_data = 0;
		return -1;
	}

	/* Have been loaded by android_image_load_separate() on fdt_addr_r */
	fdt_addr_r = env_get_ulong("fdt_addr_r", 16, 0);
	if (!fdt_addr_r) {
		printf("No Found FDT Load Address.\n");
		return -1;
	}

	*rd_data = fdt_addr_r;

	debug("FDT load addr 0x%08x size %u KiB\n",
	      hdr->second_addr, DIV_ROUND_UP(hdr->second_size, 1024));

	return 0;
}

#if defined(CONFIG_DM_CRYPTO) && defined(CONFIG_ANDROID_BOOT_IMAGE_HASH)
static void print_hash(const char *label, u8 *hash, int len)
{
	int i;

	printf("%s:\n    0x", label ? : "Hash");
	for (i = 0; i < len; i++)
		printf("%02x", hash[i]);
	printf("\n");
}
#endif

typedef enum {
	IMG_KERNEL,
	IMG_RAMDISK,
	IMG_SECOND,
	IMG_RECOVERY_DTBO,
	IMG_RK_DTB,	/* within resource.img in second position */
	IMG_DTB,
	IMG_MAX,
} img_t;

static int image_read(img_t img, struct andr_img_hdr *hdr,
		      ulong blkstart, void *ram_base,
		      struct udevice *crypto)
{
	struct blk_desc *desc = rockchip_get_bootdev();
	__maybe_unused u32 sizesz;
	ulong pgsz = hdr->page_size;
	ulong blksz = desc->blksz;
	ulong blkcnt, blkoff;
	ulong offset = 0;
	ulong datasz;
	void *ramdst;
	int ret = 0;

	switch (img) {
	case IMG_KERNEL:
		offset = 0; /* include a page_size(image header) */
		blkcnt = DIV_ROUND_UP(hdr->kernel_size + pgsz, blksz);
		ramdst = (void *)env_get_ulong("android_addr_r", 16, 0);
		datasz = hdr->kernel_size + pgsz;
		sizesz = sizeof(hdr->kernel_size);
		if (!sysmem_alloc_base(MEM_KERNEL,
				(phys_addr_t)ramdst, blkcnt * blksz))
			return -ENOMEM;
		break;
	case IMG_RAMDISK:
		offset = pgsz + ALIGN(hdr->kernel_size, pgsz);
		blkcnt = DIV_ROUND_UP(hdr->ramdisk_size, blksz);
		ramdst = (void *)env_get_ulong("ramdisk_addr_r", 16, 0);
		datasz = hdr->ramdisk_size;
		sizesz = sizeof(hdr->ramdisk_size);
		if (datasz && !sysmem_alloc_base(MEM_RAMDISK,
				(phys_addr_t)ramdst, blkcnt * blksz))
			return -ENOMEM;
		break;
	case IMG_SECOND:
		offset = pgsz +
			 ALIGN(hdr->kernel_size, pgsz) +
			 ALIGN(hdr->ramdisk_size, pgsz);
		blkcnt = DIV_ROUND_UP(hdr->second_size, blksz);
		datasz = hdr->second_size;
		sizesz = sizeof(hdr->second_size);
		ramdst = malloc(blkcnt * blksz);
		break;
	case IMG_RECOVERY_DTBO:
		offset = pgsz +
			 ALIGN(hdr->kernel_size, pgsz) +
			 ALIGN(hdr->ramdisk_size, pgsz) +
			 ALIGN(hdr->second_size, pgsz);
		blkcnt = DIV_ROUND_UP(hdr->recovery_dtbo_size, blksz);
		datasz = hdr->recovery_dtbo_size;
		sizesz = sizeof(hdr->recovery_dtbo_size);
		ramdst = malloc(blkcnt * blksz);
		break;
	case IMG_DTB:
		offset = pgsz +
			 ALIGN(hdr->kernel_size, pgsz) +
			 ALIGN(hdr->ramdisk_size, pgsz) +
			 ALIGN(hdr->second_size, pgsz) +
			 ALIGN(hdr->recovery_dtbo_size, pgsz);
		blkcnt = DIV_ROUND_UP(hdr->dtb_size, blksz);
		datasz = hdr->dtb_size;
		sizesz = sizeof(hdr->dtb_size);
		ramdst = malloc(blkcnt * blksz);
		break;
	case IMG_RK_DTB:
#ifdef CONFIG_RKIMG_BOOTLOADER
		/* No going further, it handles DTBO, HW-ID, etc */
		ramdst = (void *)env_get_ulong("fdt_addr_r", 16, 0);
		if (gd->fdt_blob != (void *)ramdst)
			ret = rockchip_read_dtb_file(ramdst);
#endif
		return ret < 0 ? ret : 0;
	default:
		return -EINVAL;
	}

	if (!ramdst) {
		printf("No memory for image(%d)\n", img);
		return -ENOMEM;
	}

	if (!blksz || !datasz)
		goto crypto_calc;

	/* load */
	if (ram_base) {
		memcpy(ramdst, (char *)((ulong)ram_base + offset), datasz);
	} else {
		blkoff = DIV_ROUND_UP(offset, blksz);
		ret = blk_dread(desc, blkstart + blkoff, blkcnt, ramdst);
		if (ret != blkcnt) {
			printf("Failed to read img(%d), ret=%d\n", img, ret);
			return -EIO;
		}
	}

crypto_calc:
	/* sha1 */
#ifdef CONFIG_DM_CRYPTO
	if (crypto) {
		if (img == IMG_KERNEL) {
			ramdst += pgsz;
			datasz -= pgsz;
		}

		crypto_sha_update(crypto, (u32 *)ramdst, datasz);
		crypto_sha_update(crypto, (u32 *)&datasz, sizesz);
	}
#endif

	return 0;
}

static int android_image_separate(struct andr_img_hdr *hdr,
				  const disk_partition_t *part,
				  void *load_address,
				  void *ram_base)
{
	ulong bstart;

	struct fdt_header *working_fdt;
        struct hw_config hw_conf;
        memset(&hw_conf, 0, sizeof(struct hw_config));
        parse_hw_config(&hw_conf);

	printf("config.txt valid = %d\n", hw_conf.valid);
	if (hw_conf.valid == 1) {
		printf("config on: 1, config off: -1, no config: 0\n");
		printf("intf.i2c1 = %d\n", hw_conf.i2c1);
		printf("intf.i2c4 = %d\n", hw_conf.i2c4);
		printf("intf.spi0 = %d\n", hw_conf.spi0);
		printf("intf.spi2 = %d\n", hw_conf.spi2);
		printf("intf.pwm2 = %d\n", hw_conf.pwm2);
		printf("intf.pwm3 = %d\n", hw_conf.pwm3);
		printf("intf.pcm = %d\n", hw_conf.pcm);
		printf("intf.pcm_i2s = %d\n", hw_conf.pcm_i2s);
		printf("intf.uart1 = %d\n", hw_conf.uart1);
		printf("intf.uart2 = %d\n", hw_conf.uart2);
		printf("intf.uart3 = %d\n", hw_conf.uart3);
		printf("intf.uart4 = %d\n", hw_conf.uart4);

		for (int i = 0; i < hw_conf.overlay_count; i++)
			printf("get overlay name: %s\n", hw_conf.overlay_file[i]);
	}

	if (android_image_check_header(hdr)) {
		printf("Bad android image header\n");
		return -EINVAL;
	}

	/* set for image_read(IMG_KERNEL, ...) */
	env_set_hex("android_addr_r", (ulong)load_address);
	bstart = part ? part->start : 0;

	/*
	 * 1. Load images to their individual target ram position
	 *    in order to disable fdt/ramdisk relocation.
	 */
#if defined(CONFIG_DM_CRYPTO) && defined(CONFIG_ANDROID_BOOT_IMAGE_HASH)
	struct udevice *dev;
	sha_context ctx;
	uchar hash[20];

	ctx.length = 0;
	ctx.algo = CRYPTO_SHA1;
	dev = crypto_get_device(ctx.algo);
	if (!dev) {
		printf("Can't find crypto device for SHA1 capability\n");
		return -ENODEV;
	}

  #ifdef CONFIG_ROCKCHIP_CRYPTO_V1
	/* v1: requires total length before sha init */
	ctx.length += hdr->kernel_size + sizeof(hdr->kernel_size) +
		      hdr->ramdisk_size + sizeof(hdr->ramdisk_size) +
		      hdr->second_size + sizeof(hdr->second_size);
	if (hdr->header_version > 0)
		ctx.length += hdr->recovery_dtbo_size +
					sizeof(hdr->recovery_dtbo_size);
	if (hdr->header_version > 1)
		ctx.length += hdr->dtb_size + sizeof(hdr->dtb_size);
  #endif
	crypto_sha_init(dev, &ctx);

	/* load, never change order ! */
	if (image_read(IMG_RK_DTB,  hdr, bstart, ram_base, NULL))
		return -1;
	if (image_read(IMG_KERNEL,  hdr, bstart, ram_base, dev))
		return -1;
	if (image_read(IMG_RAMDISK, hdr, bstart, ram_base, dev))
		return -1;
	if (image_read(IMG_SECOND,  hdr, bstart, ram_base, dev))
		return -1;
	if (hdr->header_version > 0) {
		if (image_read(IMG_RECOVERY_DTBO, hdr, bstart, ram_base, dev))
			return -1;
	}
	if (hdr->header_version > 1) {
		if (image_read(IMG_DTB, hdr, bstart, ram_base, dev))
			return -1;
	}

	crypto_sha_final(dev, &ctx, hash);
	if (memcmp(hash, hdr->id, 20)) {
		print_hash("Hash from header", (u8 *)hdr->id, 20);
		print_hash("Hash real", (u8 *)hash, 20);
		return -EBADFD;
	} else {
		printf("Image hash OK\n");
	}

#else /* !(CONFIG_DM_CRYPTO && CONFIG_ANDROID_BOOT_IMAGE_HASH) */
	if (image_read(IMG_RK_DTB,  hdr, bstart, ram_base, NULL))
		return -1;
	if (image_read(IMG_KERNEL,  hdr, bstart, ram_base, NULL))
		return -1;
	if (image_read(IMG_RAMDISK, hdr, bstart, ram_base, NULL))
		return -1;
	if (image_read(IMG_SECOND,  hdr, bstart, ram_base, NULL))
		return -1;
	if (hdr->header_version > 0) {
		if (image_read(IMG_RECOVERY_DTBO, hdr, bstart, ram_base, NULL))
			return -1;
	}
	if (hdr->header_version > 1) {
		if (image_read(IMG_DTB, hdr, bstart, ram_base, NULL))
			return -1;
	}
#endif

	/* 2. Disable fdt/ramdisk relocation, it saves boot time */
	env_set("bootm-no-reloc", "y");

	working_fdt = resize_working_fdt();
        if (working_fdt != NULL) {
                if(hw_conf.valid)
                        handle_hw_conf(NULL, working_fdt, &hw_conf);
        }

	return 0;
}

/*
 * 'boot_android' cmd use "kernel_addr_r" as default load address !
 * We update it according to compress type and "kernel_addr_c/r".
 */
int android_image_parse_comp(struct andr_img_hdr *hdr, ulong *load_addr)
{
	ulong kernel_addr_c;
	int comp;

	kernel_addr_c = env_get_ulong("kernel_addr_c", 16, 0);
	comp = android_image_parse_kernel_comp(hdr);

#ifdef CONFIG_ARM64
	/*
	 * On 64-bit kernel, assuming use IMAGE by default.
	 *
	 * kernel_addr_c is for LZ4-IMAGE but maybe not defined.
	 * kernel_addr_r is for IMAGE.
	 */
	if (comp != IH_COMP_NONE) {
		ulong comp_addr;

		if (kernel_addr_c) {
			comp_addr = kernel_addr_c;
		} else {
			printf("Warn: No \"kernel_addr_c\"\n");
			comp_addr = CONFIG_SYS_SDRAM_BASE + 0x2000000;/* 32M */
			env_set_hex("kernel_addr_c", comp_addr);
		}

		*load_addr = comp_addr - hdr->page_size;
	}
#else
	/*
	 * On 32-bit kernel:
	 *
	 * The input load_addr is from env value: "kernel_addr_r", it has
	 * different role depends on whether kernel_addr_c is defined:
	 *
	 * - kernel_addr_r is for lz4/zImage if kernel_addr_c if [not] defined.
	 * - kernel_addr_r is for IMAGE if kernel_addr_c is defined.
	 */
	if (comp == IH_COMP_NONE) {
		if (kernel_addr_c) {
			/* input load_addr is for Image, nothing to do */
		} else {
			/* input load_addr is for lz4/zImage, set default addr for Image */
			*load_addr = CONFIG_SYS_SDRAM_BASE + 0x8000;
			env_set_hex("kernel_addr_r", *load_addr);

			*load_addr -= hdr->page_size;
		}
	} else {
		if (kernel_addr_c) {
			/* input load_addr is for Image, so use another for lz4/zImage */
			*load_addr = kernel_addr_c - hdr->page_size;
		} else {
			/* input load_addr is for lz4/zImage, nothing to do */
		}
	}
#endif

	env_set_ulong("os_comp", comp);
	return comp;
}

void android_image_set_decomp(struct andr_img_hdr *hdr, int comp)
{
	ulong kernel_addr_r;

	/* zImage handles decompress itself */
	if (comp != IH_COMP_NONE && comp != IH_COMP_ZIMAGE) {
		kernel_addr_r = env_get_ulong("kernel_addr_r", 16, 0x02080000);
		android_image_set_kload(hdr, kernel_addr_r);
		android_image_set_comp(hdr, comp);
	} else {
		android_image_set_comp(hdr, IH_COMP_NONE);
	}
}

static int android_image_load_separate(struct andr_img_hdr *hdr,
				       const disk_partition_t *part,
				       void *load_addr)
{
	return android_image_separate(hdr, part, load_addr, NULL);
}

int android_image_memcpy_separate(struct andr_img_hdr *hdr, ulong *load_addr)
{
	ulong comp_addr = *load_addr;
	int comp;

	comp = android_image_parse_comp(hdr, &comp_addr);
	if (comp_addr == (ulong)hdr)
		return 0;

	if (android_image_separate(hdr, NULL, (void *)comp_addr, hdr))
		return -1;

	*load_addr = comp_addr;
	android_image_set_decomp((void *)comp_addr, comp);

	return 0;
}

long android_image_load(struct blk_desc *dev_desc,
			const disk_partition_t *part_info,
			unsigned long load_address,
			unsigned long max_size) {
	struct andr_img_hdr *hdr;
	u32 blksz = dev_desc->blksz;
	u32 pszcnt, hdrcnt, kercnt;
	int comp, ret;

	if (max_size < part_info->blksz)
		return -1;

	/*
	 * read Android image header and leave enough space for page_size align
	 * and kernel image header(1 block maybe enough).
	 *
	 * ANDROID_ROCKCHIP_LEGACY_PAGE_SIZE is defined by rockchip legacy
	 * mkboot tool(SDK version < 8.1) and larger than Google defined.
	 *
	 * To compatible this, we malloc enough buffer but only read android
	 * header and kernel image(1 block) from storage(ignore page size).
	 */
	kercnt = 1;
	hdrcnt = DIV_ROUND_UP(sizeof(*hdr), blksz);
	pszcnt = DIV_ROUND_UP(ANDROID_ROCKCHIP_LEGACY_PAGE_SIZE, blksz);

	hdr = memalign(ARCH_DMA_MINALIGN, (hdrcnt + pszcnt + kercnt) * blksz);
	if (!hdr) {
		printf("No memory\n");
		return -1;
	}

	if (blk_dread(dev_desc, part_info->start, hdrcnt, hdr) != hdrcnt) {
		printf("Failed to read image header\n");
		goto fail;
	}

	if (android_image_check_header(hdr) != 0) {
		printf("** Invalid Android Image header **\n");
		goto fail;
	}

	/*
	 * Update and skip pszcnt(hdr is included) according to hdr->page_size,
	 * reading kernel image for compress validation.
	 */
	pszcnt = DIV_ROUND_UP(hdr->page_size, blksz);
	if (blk_dread(dev_desc, part_info->start + pszcnt, kercnt,
		      (void *)((ulong)hdr + hdr->page_size)) != kercnt) {
		printf("Failed to read kernel header\n");
		goto fail;
	}

	load_address -= hdr->page_size;

	/* Let's load kernel now ! */
	comp = android_image_parse_comp(hdr, &load_address);
	ret = android_image_load_separate(hdr, part_info, (void *)load_address);
	if (ret) {
		printf("Failed to load android image\n");
		goto fail;
	}
	android_image_set_decomp((void *)load_address, comp);

	debug("Loading Android Image to 0x%08lx\n", load_address);

	free(hdr);
	return load_address;

fail:
	free(hdr);
	return -1;
}

#if !defined(CONFIG_SPL_BUILD)
/**
 * android_print_contents - prints out the contents of the Android format image
 * @hdr: pointer to the Android format image header
 *
 * android_print_contents() formats a multi line Android image contents
 * description.
 * The routine prints out Android image properties
 *
 * returns:
 *     no returned results
 */
void android_print_contents(const struct andr_img_hdr *hdr)
{
	const char * const p = IMAGE_INDENT_STRING;
	/* os_version = ver << 11 | lvl */
	u32 os_ver = hdr->os_version >> 11;
	u32 os_lvl = hdr->os_version & ((1U << 11) - 1);
	u32 header_version = hdr->header_version;

	printf("%skernel size:      %x\n", p, hdr->kernel_size);
	printf("%skernel address:   %x\n", p, hdr->kernel_addr);
	printf("%sramdisk size:     %x\n", p, hdr->ramdisk_size);
	printf("%sramdisk addrress: %x\n", p, hdr->ramdisk_addr);
	printf("%ssecond size:      %x\n", p, hdr->second_size);
	printf("%ssecond address:   %x\n", p, hdr->second_addr);
	printf("%stags address:     %x\n", p, hdr->tags_addr);
	printf("%spage size:        %x\n", p, hdr->page_size);
	printf("%sheader_version:   %x\n", p, header_version);
	/* ver = A << 14 | B << 7 | C         (7 bits for each of A, B, C)
	 * lvl = ((Y - 2000) & 127) << 4 | M  (7 bits for Y, 4 bits for M) */
	printf("%sos_version:       %x (ver: %u.%u.%u, level: %u.%u)\n",
	       p, hdr->os_version,
	       (os_ver >> 7) & 0x7F, (os_ver >> 14) & 0x7F, os_ver & 0x7F,
	       (os_lvl >> 4) + 2000, os_lvl & 0x0F);
	printf("%sname:             %s\n", p, hdr->name);
	printf("%scmdline:          %s\n", p, hdr->cmdline);

	if (header_version >= 1) {
		printf("%srecovery dtbo size:    %x\n", p, hdr->recovery_dtbo_size);
		printf("%srecovery dtbo offset:  %llx\n", p, hdr->recovery_dtbo_offset);
		printf("%sheader size:           %x\n", p, hdr->header_size);
	}

	if (header_version >= 2) {
		printf("%sdtb size:              %x\n", p, hdr->dtb_size);
		printf("%sdtb addr:              %llx\n", p, hdr->dtb_addr);
	}
}
#endif
