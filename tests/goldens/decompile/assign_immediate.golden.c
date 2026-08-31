void assign_immediate(void) {
    *(uint64_t*)(rsp - 0x8) = 0x2a;
    return;
}
