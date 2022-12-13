%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0": ["0x4008000000000000", "0x4008000000000000", "0x4008000000000000", "0x4008000000000000"],
    "XMM1": ["0x4000000000000000", "0x4000000000000000", "0x4000000000000000", "0x4000000000000000"],
    "XMM2": ["0x4018000000000000", "0x4018000000000000", "0x0000000000000000", "0x0000000000000000"],
    "XMM3": ["0x4018000000000000", "0x4018000000000000", "0x0000000000000000", "0x0000000000000000"],
    "XMM4": ["0x4018000000000000", "0x4018000000000000", "0x4018000000000000", "0x4018000000000000"],
    "XMM5": ["0x4018000000000000", "0x4018000000000000", "0x4018000000000000", "0x4018000000000000"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif

lea rdx, [rel .data]

vmovapd ymm0, [rdx]
vmovapd ymm1, [rdx + 32]

; Memory operand
vmulpd xmm2, xmm0, [rdx + 32]
vmulpd ymm4, ymm0, [rdx + 32]

; Register only
vmulpd xmm3, xmm0, xmm1
vmulpd ymm5, ymm1, ymm0

hlt

align 32
.data:
dq 0x4008000000000000
dq 0x4008000000000000
dq 0x4008000000000000
dq 0x4008000000000000

dq 0x4000000000000000
dq 0x4000000000000000
dq 0x4000000000000000
dq 0x4000000000000000
