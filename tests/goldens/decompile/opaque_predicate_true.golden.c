void opaque_predicate_true(void) {
    t0 = (int64_t)rax * rax;
    /* cmp t0, 0x0; sets flags */
    rbx = rbx + 0x1;
    *(uint64_t*)(rsp - 0x8) = rbx;
    return;
}
