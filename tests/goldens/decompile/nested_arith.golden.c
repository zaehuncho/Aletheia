uint64_t nested_arith(int64_t arg0) {
    /* args: arg0 = rcx */
    t0 = rbx - 0x3;
    t1 = (int64_t)rcx * 0x2;
    rax = t0 + t1;
    *(uint64_t*)(rsp - 0x8) = rax;
    return;
}
