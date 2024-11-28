# Runtime-return-value-override-
- this is a meothd to override the return value of a function.
# Steps :
- overriding the return address
- overrding the eax (32bit) or rax (64bit) because the majority of the functions stores its return value in the eax/rax except for floats which are stored in xmm0
- jumping back to the original return address

# NOTE : 
- in this exemple my target function is user32!MessageBoxA
- i used hde32 and hde64 for deassembling the target function bytes to get the required trampoline size, you can get them from github.
