#!/bin/bash
#
# Copyright (C) 2020 Rockchip Electronics Co., Ltd
#
# SPDX-License-Identifier:     GPL-2.0+
#

# Process args and auto set variables
source ./${srctree}/arch/arm/mach-rockchip/make_fit_args.sh

rm -f ${srctree}/*.digest ${srctree}/*.bin.gz

if [ "${COMPRESSION}" == "gzip" ]; then
	SUFFIX=".gz"
else
	COMPRESSION="none"
	SUFFIX=
fi

if grep  -q '^CONFIG_FIT_ENABLE_RSASSA_PSS_SUPPORT=y' .config ; then
	ALGO_PADDING="				padding = \"pss\";"
fi

# digest
if [ "${COMPRESSION}" == "gzip" ]; then
	openssl dgst -sha256 -binary -out ${srctree}/u-boot-nodtb.digest ${srctree}/u-boot-nodtb.bin
	openssl dgst -sha256 -binary -out ${srctree}/tee.digest ${srctree}/tee.bin
	gzip -k -f -9 ${srctree}/tee.bin
	UBOOT_SZ=`ls -l u-boot-nodtb.bin | awk '{ print $5 }'`
	if [ ${UBOOT_SZ} -gt 0 ]; then
		gzip -k -f -9 ${srctree}/u-boot-nodtb.bin
	else
		touch ${srctree}/u-boot-nodtb.bin.gz
	fi
	if [ ! -z "${MCU_LOAD_ADDR}" ]; then
		openssl dgst -sha256 -binary -out ${srctree}/mcu.digest ${srctree}/mcu.bin
		gzip -k -f -9 ${srctree}/mcu.bin
	fi

	UBOOT_DIGEST="			digest {
				value = /incbin/(\"./u-boot-nodtb.digest\");
				algo = \"sha256\";
			};"
	TEE_DIGEST="			digest {
				value = /incbin/(\"./tee.digest\");
				algo = \"sha256\";
			};"
	MCU_DIGEST="			digest {
				value = /incbin/(\"./mcu.digest\");
				algo = \"sha256\";
			};"
fi

# mcu
if [ ! -z "${MCU_LOAD_ADDR}" ]; then
	MCU_NODE="		mcu {
			description = \"mcu\";
			type = \"standalone\";
			arch = \"riscv\";
			data = /incbin/(\"./mcu.bin${SUFFIX}\");
			compression = \"${COMPRESSION}\";
			load = <0x"${MCU_LOAD_ADDR}">;
			hash {
				algo = \"sha256\";
			};
${MCU_DIGEST}
		};"
	MCU_STANDALONE="			standalone = \"mcu\";"
	SIGN_IMAGES="			        sign-images = \"fdt\", \"firmware\", \"loadables\", \"standalone\";"
else
	SIGN_IMAGES="			        sign-images = \"fdt\", \"firmware\", \"loadables\";"
fi

KERN_DTB=`sed -n "/CONFIG_EMBED_KERNEL_DTB_PATH=/s/CONFIG_EMBED_KERNEL_DTB_PATH=//p" .config | tr -d '"'`
if [ -z "${KERN_DTB}" ]; then
	return;
fi
if [ -f ${srctree}/${KERN_DTB} ]; then
	PROP_KERN_DTB=', "kern-fdt"';
	KFDT_NODE="		kern-fdt {
			description = \"${KERN_DTB}\";
			data = /incbin/(\"${KERN_DTB}\");
			type = \"flat_dt\";
			arch = \"${ARCH}\";
			compression = \"none\";
			hash {
				algo = \"sha256\";
			};
		};"
fi
########################################################################################################
THIS_PLAT=`sed -n "/CONFIG_DEFAULT_DEVICE_TREE/p" .config | awk -F "=" '{ print $2 }' | tr -d '"'`

cat << EOF
/*
 * Copyright (C) 2020 Rockchip Electronic Co.,Ltd
 *
 * Simple U-boot fit source file containing U-Boot, dtb and optee
 */

/dts-v1/;

/ {
	description = "FIT Image with U-Boot/OP-TEE/MCU";
	#address-cells = <1>;

	images {
		uboot {
			description = "U-Boot (32-bit)";
			data = /incbin/("./u-boot-nodtb.bin${SUFFIX}");
			type = "standalone";
			arch = "arm";
			os = "U-Boot";
			compression = "${COMPRESSION}";
			load = <${UBOOT_LOAD_ADDR}>;
			hash {
				algo = "sha256";
			};
EOF
echo "${UBOOT_DIGEST}"
cat << EOF
		};
		optee {
			description = "OP-TEE";
			data = /incbin/("./tee.bin${SUFFIX}");
			type = "firmware";
			arch = "arm";
			os = "op-tee";
			compression = "${COMPRESSION}";
			load = <0x${TEE_LOAD_ADDR}>;
			entry = <0x${TEE_LOAD_ADDR}>;
			hash {
				algo = "sha256";
			};
EOF
echo "${TEE_DIGEST}"
cat << EOF
		};
		fdt {
			description = "U-Boot dtb";
			data = /incbin/("./u-boot.dtb");
			type = "flat_dt";
			arch = "${ARCH}";
			compression = "none";
			hash {
				algo = "sha256";
			};
		};
EOF
echo "${KFDT_NODE}"
echo "${MCU_NODE}"
cat  << EOF
	};

	configurations {
		default = "conf";
		conf {
			description = "${THIS_PLAT}";
			rollback-index = <0x0>;
			firmware = "optee";
			loadables = "uboot";
			fdt = "fdt"${PROP_KERN_DTB};
EOF
echo "${MCU_STANDALONE}"
cat  << EOF
			signature {
				algo = "sha256,rsa2048";
				${ALGO_PADDING}
				key-name-hint = "dev";
EOF
echo "${SIGN_IMAGES}"
cat  << EOF
			};
		};
	};
};
EOF
