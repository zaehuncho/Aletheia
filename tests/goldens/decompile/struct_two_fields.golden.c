void struct_two_fields(void* arg0) {
    /* args: arg0 = rcx */
    struct auto_1 { uint64_t field_0; uint64_t field_8; };
    ((struct auto_1*)rcx)->field_0 = 0x1;
    ((struct auto_1*)rcx)->field_8 = 0x2;
    return;
}
