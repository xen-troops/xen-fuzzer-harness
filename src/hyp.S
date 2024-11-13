#include <zephyr/toolchain.h>
#include <zephyr/linker/sections.h>
#include <zephyr/xen/public/arch-arm.h>
#include <zephyr/xen/public/xen.h>

_ASM_FILE_PROLOGUE

GTEXT(afl_hypercall)
SECTION_FUNC(TEXT, afl_hypercall)
	mov x16, x6
	hvc XEN_HYPERCALL_TAG
	ret


