uint64_t if_only(void) {
    if (rax == 0x0) {
        rax = rax + 0x1;
    }
    rax = phi(rax, rax);
    *(uint64_t*)(rsp - 0x8) = rax;
    return;
}
