# PLT trampoline for lazy binding
    .text
    .globl trampoline
    .hidden trampoline
    .type trampoline, @function
    .align 16

trampoline:

# Your code here
	popq %r10
	popq %r11
	pushq %rdi
	pushq %rsi
	pushq %rbx
	movq %rsp, %rbx
	movq %r10, %rdi
	movq %r11, %rsi
    call runtimeResolve
    movq %rbx, %rsp
    popq %rbx
    popq %rsi
    popq %rdi
    jmpq *%rax
# Your code hoere

