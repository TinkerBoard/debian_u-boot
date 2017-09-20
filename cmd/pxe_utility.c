/*
 * Copyright (c) 2017, ASUS CORPORATION.  All rights reserved.
 */ 

#include <common.h>
#include <command.h>
#include <malloc.h>
#include <mapmem.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <errno.h>
#include <linux/list.h>
#include <fs.h>
#include <asm/io.h>
#include <version.h>
#include <libfdt.h>

#include "menu.h"
#include "cli.h"

#define DTS_OVERLAY_PROPERTY_LENGTH 10
#define DTS_OVERLAY_PREFIX "/overlays/"
#define DTS_PREFIX_LENGTH 10

#define DTS_PARAM_PROPERTY_LENGTH 8
#define MAX_PARAM_NAME_LENGTH 128

#define MAX_OVERLAY_NAME_LENGTH 128

struct hw_config
{
        int valid;
        int i2c1;
        int i2c4;
        int spi2;
        int pwm2;
        int pwm3;
        int pcm;
        int uart1;
        int dts_overlay;
        char dts_overlay_name[MAX_OVERLAY_NAME_LENGTH];
	int dts_param;
	char dts_param_name[MAX_PARAM_NAME_LENGTH];
        int spi0;
        int uart2;
        int uart3;
        int uart4;
        int pcm_i2s;
};

extern char *from_env(const char *envvar);
extern int get_relfile(cmd_tbl_t *cmdtp, const char *file_path, unsigned long file_addr);

static unsigned long hw_skip_comment(char *text)
{
        int i = 0;
        if(*text == '#')
        {
                while(*(text + i) != 0x00)
                {
                        if(*(text + (i++)) == 0x0a)
                                break;
                }
        }

        return i;
}

static unsigned long hw_skip_line(char *text)
{
        if(*text == 0x0a)
        {
                return 1;
        }
        else
        {
                return 0;
        }

}

static unsigned long get_value(char *text, struct hw_config *hw_conf)
{
        int i = 0;
        if(memcmp(text, "i2c1=",  5) == 0)
        {
                i = 5;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->i2c1 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->i2c1 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "i2c4=",  5) == 0)
        {
                i = 5;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->i2c4 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->i2c4 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "spi2=",  5) == 0)
        {
                i = 5;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->spi2 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->spi2 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "pwm2=",  5) == 0)
        {
                i = 5;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->pwm2 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->pwm2 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "pwm3=",  5) == 0)
        {
                i = 5;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->pwm3 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->pwm3 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "pcm=",  4) == 0)
        {
                i = 4;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->pcm = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->pcm = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "uart1=",  6) == 0)
        {
                i = 6;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->uart1 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->uart1 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "dtoverlay=",  10) == 0)
        {
                int name_length;
                int j = DTS_OVERLAY_PROPERTY_LENGTH; //dts_overlay file offset
                i = j;

                while(*(text + j) != 0x00)
                {
                        if(*(text + j) == 0x0a)
                                break;
                        j++;
                }

                name_length = j - i;
                i = j;

                //printf("dts_overlay name length = %d\n", name_length);
                if(name_length && name_length < MAX_OVERLAY_NAME_LENGTH)
                {
                        memcpy(hw_conf->dts_overlay_name, DTS_OVERLAY_PREFIX,
                                DTS_PREFIX_LENGTH);
                        memcpy(hw_conf->dts_overlay_name + DTS_PREFIX_LENGTH,
                                text + DTS_OVERLAY_PROPERTY_LENGTH, name_length);
                        memcpy(hw_conf->dts_overlay_name + DTS_PREFIX_LENGTH + name_length,
                                ".dtbo", 5);
                        hw_conf->dts_overlay_name[DTS_PREFIX_LENGTH + name_length + 5] = 0x00;
                        printf("dtoverlay name = %s\n", hw_conf->dts_overlay_name);
                        hw_conf->dts_overlay = 1;
                }
                else
                {
                                printf("Invalid dts overlay file name\n");
                }
        }
        else if(memcmp(text, "dtparam=",  8) == 0)
        {
                int param_length;
                int j = DTS_PARAM_PROPERTY_LENGTH;
                i = j;

                while(*(text + j) != 0x00)
                {
                        if(*(text + j) == 0x0a)
                                break;
                        j++;
                }

                param_length = j - i;
                i = j;

                if(param_length && param_length < MAX_PARAM_NAME_LENGTH)
                {
                        memcpy(hw_conf->dts_param_name, text + DTS_PARAM_PROPERTY_LENGTH, param_length);
                        hw_conf->dts_param_name[param_length] = 0x00;
                        //printf("dtparam = %s\n", hw_conf->dts_param_name);
                        hw_conf->dts_param = 1;
                }
                else
                {
                                printf("Invalid dts parameter\n");
                }
        }
        else if(memcmp(text, "spi0=",  5) == 0)
        {
                i = 5;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->spi0 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->spi0 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "uart2=",  6) == 0)
        {
                i = 6;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->uart2 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->uart2 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "uart3=",  6) == 0)
        {
                i = 6;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->uart3 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->uart3 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "uart4=",  6) == 0)
        {
                i = 6;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->uart4 = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->uart4 = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }
        else if(memcmp(text, "pcm_i2s=",  8) == 0)
        {
                i = 8;
                if(memcmp(text + i, "on", 2) == 0)
                {
                        hw_conf->pcm_i2s = 1;
                        i = i + 2;
                }
                else if(memcmp(text + i, "off", 3) == 0)
                {
                        hw_conf->pcm_i2s = 0;
                        i = i + 3;
                }
                else
                        goto invalid_line;
        }

        else
                goto invalid_line;

        while(*(text + i) != 0x00)
        {
                if(*(text + (i++)) == 0x0a)
                        break;
        }
        return i;

invalid_line:
        //It's not a legal line, skip it.
        //printf("get_value: illegal line\n");
        while(*(text + i) != 0x00)
        {
                if(*(text + (i++)) == 0x0a)
                        break;
        }
        return i;
}                                                        

static unsigned long hw_parse_property(char *text, struct hw_config *hw_conf)
{
        int i = 0;
        if(memcmp(text, "intf:",  5) == 0)
        {
                i = 5;
                i = i + get_value(text + i, hw_conf);
        }
        else
        {
                //printf("hw_parse_property: illegal line\n");
                //It's not a legal line, skip it.
                while(*(text + i) != 0x00)
                {
                        if(*(text + (i++)) == 0x0a)
                                break;
                }
        }
        return i;
}

void parse_hw_config(cmd_tbl_t *cmdtp, struct hw_config *hw_conf)
{
        unsigned long file_addr, size, count, offset = 0;
        char *envaddr, *conf_size;

        int valid = 0;

        envaddr = from_env("hw_conf_addr_r");

        if (!envaddr)
                goto end;

        if (strict_strtoul(envaddr, 16, &file_addr) < 0)
                goto end;

        if(get_relfile(cmdtp, "/hw_intf.conf", file_addr) < 0)
                goto end;


        conf_size = from_env("filesize");
        if (strict_strtoul(conf_size, 16, &size) < 0)
                goto end;
        valid = 1;
        //printf("hw_conf size = %d\n", size);

        *((char *)file_addr + size) = 0x00;

        while(offset != size)
        {
                count = hw_skip_comment((char *)(file_addr + offset));
                if(count > 0)
                {
                        offset = offset + count;
                        //printf("find comment = %d\n", offset);
                        continue;
                }
                count = hw_skip_line((char *)(file_addr + offset));
                if(count > 0)
                {
                        offset = offset + count;
                        //printf("find line %d\n", offset);
                        continue;
                }
                count = hw_parse_property((char *)(file_addr + offset), hw_conf);
                if(count > 0)
                {
                        offset = offset + count;
                        continue;
                }
        }
        //printf("offset = %d\n", offset);
end:
        hw_conf->valid = valid;
}
