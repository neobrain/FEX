%ifdef CONFIG
{
  "RegData": {
    "XMM0":  ["0x4142434445464748", "0x6162636465666768"],
    "XMM1":  ["0x5152535455565758", "0x6162636465666768"],
    "XMM2":  ["0x4142434445464748", "0x7172737475767778"],
    "XMM3":  ["0x5152535455565758", "0x7172737475767778"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif

mov rdx, 0xe0000000

mov rax, 0x4142434445464748
mov [rdx + 8 * 0], rax
mov rax, 0x5152535455565758
mov [rdx + 8 * 1], rax

mov rax, 0x6162636465666768
mov [rdx + 8 * 2], rax
mov rax, 0x7172737475767778
mov [rdx + 8 * 3], rax

movapd xmm0, [rdx + 8 * 0]
movapd xmm1, [rdx + 8 * 0]
movapd xmm2, [rdx + 8 * 0]
movapd xmm3, [rdx + 8 * 0]
movapd xmm4, [rdx + 8 * 2]

shufpd xmm0, xmm4, 0
shufpd xmm1, xmm4, 1
shufpd xmm2, xmm4, 2
shufpd xmm3, xmm4, 3

hlt
