uint64_t sub_and_return(unknown_t arg0) {
    /* args: arg0 = rcx */
    rax = rbx - rcx;
    *(uint64_t*)(rsp - 0x8) = rax;
    return;
}
