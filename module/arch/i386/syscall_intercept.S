/* System call intercept function
 */

.global syscall_intercept

syscall_intercept:
    pushl   %eax                    /* Save system call no */
   
    /*
     * Arguments to pre-syscall handler will be:
     *     - system call number
     *     - Return address of system call handler
     *     - Parameters to system call
     */
    call    pre_syscall_callback    /* Pre-call */
    cmpl    $0, %eax                /* Did we get a NULL? (process not monitored) */
    je      original_call           /* Just call original handler */
    cmpb    $1, (%eax)              /* Have we replayed? */
    je      replay_return           /* Yes... */
original_call:
    popl    %eax                    /* No - restore syscall number */

    add     $4, %esp                            /* Remove return address */
    call    *original_sys_call_table(,%eax,4)   /* Call original handler */

original_call_return:
    pushl   $0                      /* We will restore original syscall return address here */
    pushl   %eax                    /* Save system call return value */

    /*
     * Arguments to post-system call handler will be:
     *     - System call return value
     *     - Space for system call return address
     *     - Parameters to system call
     */
    call    post_syscall_callback   /* Post-call */
    movl    %eax, 4(%esp)           /* Restore return address */
    popl    %eax                    /* Restore system call return value */

intercept_return:
    ret

replay_return:
    add     $4, %esp                /* Remove saved system call number from stack */
    movl    1(%eax), %eax           /* Set replayed return value */
    ret
