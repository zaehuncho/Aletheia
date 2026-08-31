uint64_t two_arg_returning_sum(unknown_t arg0, unknown_t arg1) {
    /* args: arg0 = rcx, arg1 = rdx */
    rax = rcx + rdx;
    *(uint64_t*)(rsp - 0x8) = rax;
    return;
}
