void stack_roundtrip(void) {
    *(uint64_t*)(rsp - 0x8) = rax;
    rbx = rax;
    *(uint64_t*)(rsp - 0x10) = rbx;
    return;
}
