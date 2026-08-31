void if_else(unknown_t arg0) {
    /* args: arg0 = rcx */
    if (rax == rbx) {
    } else {
    }
    rcx = phi(0x1, 0x2);
    *(uint64_t*)(rsp - 0x8) = rcx;
    return;
}
