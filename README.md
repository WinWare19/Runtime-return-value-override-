# Runtime-return-value-override-
- this is a meothd to override the return value of a function.
# Steps :
- overriding the return address
- overrding the eax (32bit) or rax (64bit) because the majority of the functions stores its return value in the eax/rax except for floats which are stored in xmm0
- jumping back to the original return address
