#include <pthread.h>
#include <linux/types.h>
#include <linux/serial_reg.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

#ifndef __BYTE_ORDER_H__
#define __BYTE_ORDER_H__

#include <asm/byteorder.h>

#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))


/* taken from include/linux/byteorder/generic.h */
#define cpu_to_le64 __cpu_to_le64
#define le64_to_cpu __le64_to_cpu
#define cpu_to_le32 __cpu_to_le32
#define le32_to_cpu __le32_to_cpu
#define cpu_to_le16 __cpu_to_le16
#define le16_to_cpu __le16_to_cpu
#define cpu_to_be64 __cpu_to_be64
#define be64_to_cpu __be64_to_cpu
#define cpu_to_be32 __cpu_to_be32
#define be32_to_cpu __be32_to_cpu
#define cpu_to_be16 __cpu_to_be16
#define be16_to_cpu __be16_to_cpu

/* change in situ versions */
#define cpu_to_le64s __cpu_to_le64s
#define le64_to_cpus __le64_to_cpus
#define cpu_to_le32s __cpu_to_le32s
#define le32_to_cpus __le32_to_cpus
#define cpu_to_le16s __cpu_to_le16s
#define le16_to_cpus __le16_to_cpus
#define cpu_to_be64s __cpu_to_be64s
#define be64_to_cpus __be64_to_cpus
#define cpu_to_be32s __cpu_to_be32s
#define be32_to_cpus __be32_to_cpus
#define cpu_to_be16s __cpu_to_be16s
#define be16_to_cpus __be16_to_cpus

#endif

#ifndef BIOS_OFFSETS_H
#define BIOS_OFFSETS_H

#define BIOS_ENTRY_SIZE(name) (name##_end - name)

#define BIOS_OFFSET__bios_int10 0x00000040
#define BIOS_OFFSET__bios_int10_end 0x0000007f
#define BIOS_OFFSET__bios_int15 0x00000080
#define BIOS_OFFSET__bios_int15_end 0x000000b8
#define BIOS_OFFSET__bios_intfake 0x00000030
#define BIOS_OFFSET__bios_intfake_end 0x00000038
#define BIOS_OFFSET____CALLER_CLOBBER 0x000000c0
#define BIOS_OFFSET____CALLER_SP 0x000000bc
#define BIOS_OFFSET____CALLER_SS 0x000000b8
#define BIOS_OFFSET__e820_query_map 0x000000c4
#define BIOS_OFFSET__int10_handler 0x00000168
#define BIOS_OFFSET__int15_handler 0x00000294
#define BIOS_OFFSET____locals 0x000000b8
#define BIOS_OFFSET____locals_end 0x000000c4
#define BIOS_OFFSET__memcpy16 0x00000000

#endif
