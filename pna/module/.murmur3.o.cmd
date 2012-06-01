cmd_/home/jason/pna/module/murmur3.o := gcc -Wp,-MD,/home/jason/pna/module/.murmur3.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/4.6.1/include  -I/usr/src/linux-headers-3.0.0-17-generic/arch/x86/include -Iarch/x86/include/generated -Iinclude  -include include/generated/autoconf.h -Iubuntu/include  -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -m64 -mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -maccumulate-outgoing-args -fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_FXSAVEQ=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -Wframe-larger-than=1024 -Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -pg -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -DCC_HAVE_ASM_GOTO -I/home/jason/pna/module/../include/  -DMODULE  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(murmur3)"  -D"KBUILD_MODNAME=KBUILD_STR(pna)" -c -o /home/jason/pna/module/.tmp_murmur3.o /home/jason/pna/module/murmur3.c

source_/home/jason/pna/module/murmur3.o := /home/jason/pna/module/murmur3.c

deps_/home/jason/pna/module/murmur3.o := \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  /usr/src/linux-headers-3.0.0-17-generic/arch/x86/include/asm/types.h \
  include/asm-generic/types.h \
  include/asm-generic/int-ll64.h \
  /usr/src/linux-headers-3.0.0-17-generic/arch/x86/include/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/linux/posix_types.h \
  include/linux/stddef.h \
  include/linux/compiler.h \
    $(wildcard include/config/sparse/rcu/pointer.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  /usr/src/linux-headers-3.0.0-17-generic/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  /usr/src/linux-headers-3.0.0-17-generic/arch/x86/include/asm/posix_types_64.h \

/home/jason/pna/module/murmur3.o: $(deps_/home/jason/pna/module/murmur3.o)

$(deps_/home/jason/pna/module/murmur3.o):
