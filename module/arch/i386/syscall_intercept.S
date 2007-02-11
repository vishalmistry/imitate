/* System call intercept function
 */

/*
if (replaying)
{
    // do copying..
    return { 1, returnval }
}
else
{
    return { 0, 0 }
}

if (return[1] == 1)
    movl return[1], %eax
    jmp ret_from_syscall

original_system_call

if (recording)
{
    // record values
}
*/

syscall_intercept:
    pushl   %eax                    /* Save system call no */
   
    /*
     * Arguments to pre-syscall handler will be:
     *     - system call number
     *     - Return address of system call handler
     *     - Parameters to system call
     */
    call    pre_syscall_callback    /* Pre-call */
    cmpb    $1, (%eax)              /* Have we replayed? */
    je      replay_return           /* Yes... */
    popl    %eax                    /* No - restore syscall number */

    add     $4, %esp                    /* Remove return address */
    call    *sys_call_table(,%eax,4)    /* Call original handler */
    
    pushl   $0                      /* We will restore original syscall return address here */
    pushl   %eax                    /* Save system call return value */

    /*
     * Arguments to post-system call handler will be:
     *     - System call return value
     *     - Space for system call return address
     *     - Parameters to system call
     */
    call    post_syscall_callback   /* Post-call */
    popl    %eax                    /* Restore system call return value */

intercept_return:
    ret

replay_return:
    add     $4, %esp                /* Remove saved system call number from stack */
    movl    1(%eax), %eax           /* Set replayed return value */
    ret
