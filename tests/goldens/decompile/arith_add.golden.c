uint64_t arith_add(void) {
    rax = rbx + 0x5;
    *(uint64_t*)(rsp - 0x8) = rax;
    return;
}
