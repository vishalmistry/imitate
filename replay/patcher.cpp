#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <imitate.h>
#include "BPatch.h"
#include "BPatch_function.h"
#include "BPatch_edge.h"

BPatch bpatch;

int main(int argc, char *argv[], char* envp[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s prog_filename prog_aruments\n", argv[0]);
        return 3;
    }
#if 0
    if (strcmp(argv[1], "prog") != 0 && strcmp(argv[1], "all"))
    {
        fprintf(stderr, "Options for patch selection are 'progonly' or 'all'\n");
        return 3;
    }
#endif
    int patchall = 0; //strcmp(argv[1], "all") != 0;

    // Create process
    BPatch_process *appProc = bpatch.processCreate(argv[1], (const char**) &(argv[2]));

    // Load pthread into the process...
    appProc->loadLibrary("libpthread.so.0");
    
    // Get the process image    
    BPatch_image *appImage = appProc->getImage();

    // Find all the instrumentable procedures
    BPatch_Vector<BPatch_function*> *functions = appImage->getProcedures();


    /*************************************************************************
     * General function search                                               *
     *************************************************************************/

    // Find the printf function
    BPatch_Vector<BPatch_function*> printfFuncs;
    appImage->findFunction("printf", printfFuncs);
    if (printfFuncs.size() == 0)
        appImage->findFunction("_printf", printfFuncs);
    if (printfFuncs.size() == 0)
        appImage->findFunction("__printf", printfFuncs);

    if(printfFuncs.size() == 0)
    {
        fprintf(stderr, "Could not find printf() function");
        return 2;
    }

    // Find the exit function
    BPatch_Vector<BPatch_function*> exitFuncs;
        appImage->findFunction("exit", exitFuncs);
    if (exitFuncs.size() == 0)
        appImage->findFunction("_exit", exitFuncs);
    if (exitFuncs.size() == 0)
        appImage->findFunction("__exit", exitFuncs);

    if(exitFuncs.size() == 0)
    {
        fprintf(stderr, "Could not find exit() function");
        return 2;
    }

    // Find the perror function
    BPatch_Vector<BPatch_function*> perrorFuncs;
    appImage->findFunction("perror", perrorFuncs);
    if (perrorFuncs.size() == 0)
        appImage->findFunction("_perror", perrorFuncs);
    if (perrorFuncs.size() == 0)
        appImage->findFunction("__perror", perrorFuncs);

    if(perrorFuncs.size() == 0)
    {
        fprintf(stderr, "Could not find perror() function");
        return 2;
    }

    BPatch_Vector<BPatch_snippet*> mainEntryBlock;

    /************************************************************************
     * Error exit call                                                      *
     ************************************************************************/

    BPatch_Vector<BPatch_snippet*> exitArgs;
    BPatch_constExpr exitCode(-2);
    exitArgs.push_back(&exitCode);

    // Open call
    BPatch_funcCallExpr exitOnErrorCall(*exitFuncs[0], exitArgs);

 
    /************************************************************************
     * Open imitate device patch                                            *
     * **********************************************************************/

    // Find main()
    BPatch_Vector<BPatch_function*> mainFunctions;
        appImage->findFunction("main", mainFunctions);
    if (mainFunctions.size() == 0)
        appImage->findFunction("_main", mainFunctions);
    if (mainFunctions.size() == 0)
        appImage->findFunction("__main", mainFunctions);

    if(mainFunctions.size() == 0)
    {
        fprintf(stderr, "Could not find main() function");
        return 2;
    }

    // find open()
    BPatch_Vector<BPatch_function*> openFunctions;
        appImage->findFunction("open64", openFunctions);
    if (openFunctions.size() == 0)
        appImage->findFunction("open", openFunctions);
    if (openFunctions.size() == 0)
        appImage->findFunction("_open", openFunctions);
    if (openFunctions.size() == 0)
        appImage->findFunction("__open", openFunctions);

    if(openFunctions.size() == 0)
    {
        fprintf(stderr, "Could not find open() function");
        return 2;
    }

    // Get main() entry point
    BPatch_Vector<BPatch_point*> *mainPoints = mainFunctions[0]->findPoint(BPatch_entry);

    // Open call arguments
    BPatch_Vector<BPatch_snippet*> openArgs;
    BPatch_constExpr fileName("/dev/imitate0");
    BPatch_constExpr fileFlags(O_RDWR);
    openArgs.push_back(&fileName);
    openArgs.push_back(&fileFlags);

    // Open call
    BPatch_funcCallExpr openDevCall(*openFunctions[0], openArgs);

    // Allocate file descriptor
    BPatch_variableExpr *devFd = appProc->malloc(*appImage->findType("int"));

    // Assign fd with result of open call
    BPatch_arithExpr openDevice(BPatch_assign, *devFd, openDevCall);

    // defFd check
    BPatch_boolExpr devFdCheck(BPatch_lt, *devFd, BPatch_constExpr(0));
    
    // perror message
    BPatch_Vector<BPatch_snippet*> devFdErrorArgs;
    BPatch_constExpr devFdErrorMsg("Opening imitate kernel device");
    devFdErrorArgs.push_back(&devFdErrorMsg);
    BPatch_funcCallExpr devFdError(*perrorFuncs[0], devFdErrorArgs);

    BPatch_Vector<BPatch_snippet*> openErrorBlock;
    openErrorBlock.push_back(&devFdError);
    openErrorBlock.push_back(&exitOnErrorCall);

    // if (devFd < 0) { perror(...) }
    BPatch_ifExpr devFdBlock(devFdCheck, BPatch_sequence(openErrorBlock));

    mainEntryBlock.push_back(&openDevice);
    mainEntryBlock.push_back(&devFdBlock);
    

    /*************************************************************************
     * Send ioctl IMITATE_APP_REPLAY to module                               *
     *************************************************************************/

    // find ioctl()
    BPatch_Vector<BPatch_function*> ioctlFunctions;
        appImage->findFunction("ioctl", ioctlFunctions);
    if (ioctlFunctions.size() == 0)
        appImage->findFunction("_ioctl", ioctlFunctions);
    if (ioctlFunctions.size() == 0)
        appImage->findFunction("__ioctl", ioctlFunctions);

    if(ioctlFunctions.size() == 0)
    {
        fprintf(stderr, "Could not find ioctl() function");
        return 2;
    }

    // ioctl() arguments
    BPatch_Vector<BPatch_snippet*> ioctlArgs;
    BPatch_constExpr operation(IMITATE_APP_REPLAY);
    fprintf(stderr, "PPID: %d\n", getppid());
    BPatch_constExpr monitorPid(getppid());
    ioctlArgs.push_back(devFd);
    ioctlArgs.push_back(&operation);
    ioctlArgs.push_back(&monitorPid);

    // ioctl() call
    BPatch_funcCallExpr ioctlCall(*ioctlFunctions[0], ioctlArgs);

    // ioctl() result check
    BPatch_boolExpr ioctlCheck(BPatch_lt, ioctlCall, BPatch_constExpr(0));
    
    // perror message
    BPatch_Vector<BPatch_snippet*> ioctlErrorArgs;
    BPatch_constExpr ioctlErrorMsg("Notifying imitate kernel driver of REPLAY");
    ioctlErrorArgs.push_back(&ioctlErrorMsg);
    BPatch_funcCallExpr ioctlError(*perrorFuncs[0], ioctlErrorArgs);

    BPatch_Vector<BPatch_snippet*> ioctlErrorBlock;
    ioctlErrorBlock.push_back(&ioctlError);
    ioctlErrorBlock.push_back(&exitOnErrorCall);

    // if (ioctl(...) < 0) { perror(...) }
    BPatch_ifExpr ioctlBlock(ioctlCheck, BPatch_sequence(ioctlErrorBlock));

    // Add ioctl check to entry block
    mainEntryBlock.push_back(&ioctlBlock);

    /*************************************************************************
     * Counter mmap()                                                        *
     *************************************************************************/

    // Find the mmap function
    BPatch_Vector<BPatch_function*> mmapFuncs;
        appImage->findFunction("mmap", mmapFuncs);
    if (mmapFuncs.size() == 0)
        appImage->findFunction("_mmap", mmapFuncs);
    if (mmapFuncs.size() == 0)
        appImage->findFunction("__mmap", mmapFuncs);

    if(mmapFuncs.size() == 0)
    {
        fprintf(stderr, "Could not find mmap() function");
        return 2;
    }

    // Allocate counter
    BPatch_variableExpr *counterAddr = appProc->malloc(sizeof(sched_counter_t*));
    sched_counter_t counterVal = 0;
    counterAddr->writeValue(&counterVal, sizeof(sched_counter_t*), false);

    // Notify kernel of address
    BPatch_Vector<BPatch_snippet*> mmapArgs;
    BPatch_constExpr mmapStart(0);
    BPatch_constExpr mmapLength(sizeof(sched_counter_t));
    BPatch_constExpr mmapProt(PROT_READ | PROT_WRITE);
    BPatch_constExpr mmapFlags(MAP_SHARED);
    BPatch_constExpr mmapOffset(0);

    mmapArgs.push_back(&mmapStart);
    mmapArgs.push_back(&mmapLength);
    mmapArgs.push_back(&mmapProt);
    mmapArgs.push_back(&mmapFlags);
    mmapArgs.push_back(devFd);
    mmapArgs.push_back(&mmapOffset);

    // mmap() call
    BPatch_funcCallExpr mmapCall(*mmapFuncs[0], mmapArgs);

    // assign result to counterAddr
    BPatch_arithExpr mmapAssign(BPatch_assign, *counterAddr, mmapCall);

    // Add to entry block
    mainEntryBlock.push_back(&mmapAssign);

    // mmap() result check
    BPatch_boolExpr mmapCheck(BPatch_eq, *counterAddr, BPatch_constExpr(MAP_FAILED));

    // perror message
    BPatch_Vector<BPatch_snippet*> mmapErrorArgs;
    BPatch_constExpr mmapErrorMsg("Memory mapping schedule (back edge) counter");
    mmapErrorArgs.push_back(&mmapErrorMsg);
    BPatch_funcCallExpr mmapError(*perrorFuncs[0], mmapErrorArgs);

    BPatch_Vector<BPatch_snippet*> mmapErrorBlock;
    mmapErrorBlock.push_back(&mmapError);
    mmapErrorBlock.push_back(&exitOnErrorCall);

    // if (mmap(...) == MAP_FAILED) { perror(...) }
    BPatch_ifExpr mmapBlock(mmapCheck, BPatch_sequence(mmapErrorBlock));

    mainEntryBlock.push_back(&mmapBlock);


    // Patch main entry
    BPatch_sequence mainEntrySeq(mainEntryBlock);
    appProc->insertSnippet(mainEntrySeq, *mainPoints);


    /*************************************************************************
     * Back-edge patching                                                    *
     *************************************************************************/

#if 0
    printf("intCounter address: %x\n PID: %d\n", intCounter->getBaseAddr(), appProc->getPid());
    fflush(stdout);
#endif

    // Find the mutex lock/unlock functions
    BPatch_Vector<BPatch_function*> mutexLockFunctions;
        appImage->findFunction("pthread_mutex_lock", mutexLockFunctions);
    if (mutexLockFunctions.size() == 0)
        appImage->findFunction("_pthread_mutex_lock", mutexLockFunctions);
    if (mutexLockFunctions.size() == 0)
        appImage->findFunction("__pthread_mutex_lock", mutexLockFunctions);

    if(mutexLockFunctions.size() == 0)
    {
        fprintf(stderr, "Could not find pthread_mutex_lock() function");
        return 2;
    }

    BPatch_Vector<BPatch_function*> mutexUnlockFunctions;
        appImage->findFunction("pthread_mutex_unlock", mutexUnlockFunctions);
    if (mutexUnlockFunctions.size() == 0)
        appImage->findFunction("_pthread_mutex_unlock", mutexUnlockFunctions);
    if (mutexUnlockFunctions.size() == 0)
        appImage->findFunction("__pthread_mutex_unlock", mutexUnlockFunctions);

    if(mutexUnlockFunctions.size() == 0)
    {
        fprintf(stderr, "Could not find pthread_mutex_unlock() function");
        return 2;
    }

    // Allocate a mutex
    pthread_mutex_t mutexValue = PTHREAD_MUTEX_INITIALIZER;
    BPatch_variableExpr *mutex = appProc->malloc(sizeof(pthread_mutex_t));
    mutex->writeValue(&mutexValue, sizeof(pthread_mutex_t), false);

    // Build mutex lock call
    BPatch_Vector<BPatch_snippet*> mutexArgs;
    BPatch_constExpr mutexAddress(mutex->getBaseAddr());

    mutexArgs.push_back(&mutexAddress);

    BPatch_funcCallExpr mutexLockCall(*mutexLockFunctions[0], mutexArgs);
    BPatch_funcCallExpr mutexUnlockCall(*mutexUnlockFunctions[0], mutexArgs);

    BPatch_arithExpr derefCounter(BPatch_deref, *counterAddr);

    // Create 'increment counter' snippet
    BPatch_arithExpr addOneToCounter(BPatch_assign, derefCounter,
        BPatch_arithExpr(BPatch_plus, derefCounter, BPatch_constExpr(1)));


    // Create step call
    // ioctl() arguments
    BPatch_Vector<BPatch_snippet*> stepIoctlArgs;
    BPatch_constExpr stepIoctlOperation(IMITATE_SET_BPOINT);
    BPatch_constExpr stepIoctlArg(0);
    stepIoctlArgs.push_back(devFd);
    stepIoctlArgs.push_back(&stepIoctlOperation);
    stepIoctlArgs.push_back(&stepIoctlArg);

    // ioctl() call
    BPatch_funcCallExpr stepIoctlCall(*ioctlFunctions[0], stepIoctlArgs);

    // stepIoctl() result check
    BPatch_boolExpr stepIoctlCheck(BPatch_lt, stepIoctlCall, BPatch_constExpr(0));
    
    // perror message
    BPatch_Vector<BPatch_snippet*> stepIoctlErrorArgs;
    BPatch_constExpr stepIoctlErrorMsg("Notifying imitate kernel driver of START_STEP");
    stepIoctlErrorArgs.push_back(&stepIoctlErrorMsg);
    BPatch_funcCallExpr stepIoctlError(*perrorFuncs[0], stepIoctlErrorArgs);

    BPatch_Vector<BPatch_snippet*> stepIoctlErrorBlock;
    stepIoctlErrorBlock.push_back(&stepIoctlError);
    stepIoctlErrorBlock.push_back(&exitOnErrorCall);

    // if (stepIoctl(...) < 0) { perror(...) }
    BPatch_ifExpr stepIoctlBlock(stepIoctlCheck, BPatch_sequence(stepIoctlErrorBlock));

    // When counter reaches 0, set breakpoint.
    BPatch_boolExpr stepCheck(BPatch_eq, derefCounter, BPatch_constExpr(0));
    BPatch_ifExpr checkStepBlock(stepCheck, stepIoctlBlock);


    BPatch_Vector<BPatch_snippet*> snippet;
    snippet.push_back(&mutexLockCall);
    snippet.push_back(&addOneToCounter);
    snippet.push_back(&checkStepBlock);
    snippet.push_back(&mutexUnlockCall);

    BPatch_sequence addOneAtomic(snippet);

    char *name = (char*) malloc(sizeof(char)*200);
    char *modname = (char*) malloc(sizeof(char)*200);
    if (! (name && modname))
    {
        fprintf(stderr, "%s %d: Out of memory!", __FILE__, __LINE__);
        return 1;
    }

    appProc->beginInsertionSet();

    // Iterate through the procedures
    for (int i = 0; i < functions->size(); i++)
    {
        (*functions)[i]->getName(name, 199);
        (*functions)[i]->getModuleName(modname, 199);
        if ((patchall && strcmp(modname, "DEFAULT_MODULE") != 0) ||
            strncmp(name, "pthread", 7) == 0 ||
            strncmp(modname, "libpthread", 10) == 0 ||
            strncmp(modname, "libdyninst", 10) == 0 ||
            (name[0] == '_' && name[1] != '_' && strncmp(modname, "libc", 4) == 0))
            continue;

        fprintf(stderr, "patcher: Patching function: '%s' (%s)", name, modname);

        // Patch back-edge for call
        if (strcmp(name, "main") != 0)
            appProc->insertSnippet(addOneAtomic, *((*functions)[i]->findPoint(BPatch_entry)));

        // Get the control flow graph for the procedure
        BPatch_flowGraph *graph = (*functions)[i]->getCFG();

        // Find the loops
        BPatch_Vector<BPatch_basicBlockLoop*> *loops = new BPatch_Vector<BPatch_basicBlockLoop*>();
        graph->getLoops(*loops);
    
        // Patch the loop back-edges
        for(int j = 0; j < loops->size(); j++)
        {
            appProc->insertSnippet(addOneAtomic, *((*loops)[j]->getBackEdge()->getPoint()));
            fprintf(stderr, ".", (int) (*loops)[j]->getBackEdge()->getPoint()->getAddress());
        }
        fprintf(stderr, "\n");

        // Free the loops found
        delete(loops);
    }

    fprintf(stderr, "Finalising patches...");
    fflush(stderr);
    appProc->finalizeInsertionSet(false);
    fprintf(stderr, "Done.\n----------------------------------------\n");

    // Clear up memory used to store the name
    free(name);
    free(modname);


#if 0
    /*************************************************************************
     * Exit point counter print patch                                        *
     *************************************************************************/

    // Patch exit() function to print out no of back branches at the end
    // Get exit() exit point
    BPatch_Vector<BPatch_point*> *exitPoints = exitFuncs[0]->findPoint(BPatch_entry);

    // Build printf() call:
    //    printf("Total Total Back-branches: %d\n", counter);

    // Build arguments to printf()
    BPatch_Vector<BPatch_snippet*> printfArgs;
    BPatch_constExpr formatString("Total Back-branches: %d\n");

    printfArgs.push_back(&formatString);
    printfArgs.push_back(&derefCounter);

    // Build call to printf()
    BPatch_funcCallExpr printfCall(*printfFuncs[0], printfArgs);

    // Patch into exit()
    appProc->insertSnippet(printfCall, *exitPoints);
#endif

    // Continue mutatee...
    appProc->continueExecution();

    // Wait for mutatee to finish
    while (!appProc->isTerminated())
    {
        bpatch.waitForStatusChange();
    }
    
    fprintf(stderr, "----------------------------------------\n");
    fprintf(stderr, "Exit - Signal: %d, Exit Code: %d\n", appProc->getExitSignal(), appProc->getExitCode());
    fprintf(stderr, "Done.\n");
    return 0;
}
