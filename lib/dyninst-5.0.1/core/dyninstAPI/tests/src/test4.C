/*
 * Copyright (c) 1996-2004 Barton P. Miller
 * 
 * We provide the Paradyn Parallel Performance Tools (below
 * described as "Paradyn") on an AS IS basis, and do not warrant its
 * validity or performance.  We reserve the right to update, modify,
 * or discontinue this software at any time.  We shall have no
 * obligation to supply such updates or modifications or any other
 * form of support to you.
 * 
 * This license is for research uses.  For such uses, there is no
 * charge. We define "research use" to mean you may freely use it
 * inside your organization for whatever purposes you see fit. But you
 * may not re-distribute Paradyn or parts of Paradyn, in any form
 * source or binary (including derivatives), electronic or otherwise,
 * to any other organization or entity without our permission.
 * 
 * (for other uses, please contact us at paradyn@cs.wisc.edu)
 * 
 * All warranties, including without limitation, any warranty of
 * merchantability or fitness for a particular purpose, are hereby
 * excluded.
 * 
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 * 
 * Even if advised of the possibility of such damages, under no
 * circumstances shall we (or any other person or entity with
 * proprietary rights in the software licensed hereunder) be liable
 * to you or any third party for direct, indirect, or consequential
 * damages of any character regardless of type of action, including,
 * without limitation, loss of profits, loss of use, loss of good
 * will, or computer failure or malfunction.  You agree to indemnify
 * us (and any other person or entity with proprietary rights in the
 * software licensed hereunder) for any and all liability it may
 * incur to third parties resulting from your use of Paradyn.
 */

// $Id: test4.C,v 1.36 2006/05/03 00:31:24 jodom Exp $
//

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#ifdef i386_unknown_nt4_0
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winbase.h>
#else
#include <unistd.h>
#endif

#include "BPatch.h"
#include "BPatch_Vector.h"
#include "BPatch_thread.h"
#include "BPatch_snippet.h"
#include "test_util.h"


const char *mutateeNameRoot = "./test4a.mutatee";

int inTest;		// current test #
int expectError;
int debugPrint = 0; // internal "mutator" tracing
int errorPrint = 0; // external "dyninst" tracing (via errorFunc)

bool forceRelocation = false;  // Force relocation upon instrumentation

void dprintf(const char *fmt, ...) {
   va_list args;
   va_start(args, fmt);

   if(debugPrint)
      vfprintf(stderr, fmt, args);

   va_end(args);

   fflush(stderr);
}

bool runAllTests = true;
const unsigned int MAX_TEST = 4;
bool runTest[MAX_TEST+1];
bool passedTest[MAX_TEST+1];
bool failedTest[MAX_TEST+1];
int threadCount = 0;
BPatch_thread *mythreads[25];

BPatch *bpatch;

/*
 * Given a string variable name and an expected value, lookup the varaible
 *    in the child process, and verify that the value matches.
 *
 */
bool verifyChildMemory(BPatch_thread *appThread, 
                       const char *name, int expectedVal)
{
     BPatch_image *appImage = appThread->getImage();

     if (!appImage) {
	 dprintf("unable to locate image for %d\n", appThread->getPid());
	 return false;
     }

     BPatch_variableExpr *var = appImage->findVariable(name);
     if (!var) {
	 dprintf("unable to located variable %s in child\n", name);
	 return false;
     }

     int actualVal;
     var->readValue(&actualVal);

     if (expectedVal != actualVal) {
	 printf("*** for %s, expected val = %d, but actual was %d\n",
		name, expectedVal, actualVal);
	 return false;
     } else {
	 dprintf("verified %s was = %d\n", name, actualVal);
	 return true;
     }
}

BPatch_thread *test2Child;
BPatch_thread *test2Parent;
BPatch_thread *test4Child;
BPatch_thread *test4Parent;


void forkFunc(BPatch_thread *parent, BPatch_thread *child)
{
  dprintf("forkFunc called with parent %p, child %p\n", parent, child);
    BPatch_image *appImage;
    BPatch_Vector<BPatch_function *> bpfv;
    BPatch_Vector<BPatch_snippet *> nullArgs;

    if (child) mythreads[threadCount++] = child;

    if (!child) {
       dprintf("in prefork for %d\n", parent->getPid());
    } else {
       dprintf("in fork of %d to %d\n", parent->getPid(), child->getPid());
    }

    if (inTest == 1) {
       // nothing to do for this case
    } else if (inTest == 2) {
       if (!child) return;	// skip prefork case

       // Make a race condition always show up -- we don't run
       // until the processes have had a chance.
#if !defined(os_windows)
       sleep(1);
#endif
       // That'll make erroneous continues break...

       // insert code into parent
       appImage = parent->getImage();
       assert(appImage);

       char *fn = "func2_3";
       if (NULL == appImage->findFunction(fn, bpfv) || !bpfv.size()
	   || NULL == bpfv[0]){
	 fprintf(stderr, "    Unable to find function %s\n",fn);
	 exit(1);
       }

       BPatch_function *func2_3_parent = bpfv[0];
       BPatch_funcCallExpr callExpr2(*func2_3_parent, nullArgs);
 
       bpfv.clear();
       char *fn2 = "func2_2";
       if (NULL == appImage->findFunction(fn2, bpfv) || !bpfv.size()
	   || NULL == bpfv[0]){
	 fprintf(stderr, "    Unable to find function %s\n",fn2);
	 exit(1);
       }

       BPatch_function *func2_2_parent = bpfv[0];
       BPatch_Vector<BPatch_point *> *point2 = func2_2_parent->findPoint(BPatch_exit);
       assert(point2);
       
       parent->insertSnippet(callExpr2, *point2);

       dprintf("MUTATEE:  after insert in fork of %d to %d\n", parent->getPid(), child->getPid());
       // insert different code into child
       appImage = child->getImage();
       assert(appImage);

       bpfv.clear();
       char *fn3 = "func2_4";
       if (NULL == appImage->findFunction(fn3, bpfv) || !bpfv.size()
	   || NULL == bpfv[0]){
	 fprintf(stderr, "    Unable to find function %s\n",fn3);
	 exit(1);
       }

       BPatch_function *func2_4_child = bpfv[0];
       BPatch_funcCallExpr callExpr1(*func2_4_child, nullArgs);

       bpfv.clear();
       char *fn4 = "func2_2";
       if (NULL == appImage->findFunction(fn4, bpfv) || !bpfv.size()
	   || NULL == bpfv[0]){
	 fprintf(stderr, "    Unable to find function %s\n",fn4);
	 exit(1);
       }

       BPatch_function *func2_2_child = bpfv[0];
       BPatch_Vector<BPatch_point *> *point1 = func2_2_child->findPoint(BPatch_exit);
       assert(point1);

       child->insertSnippet(callExpr1, *point1);

       dprintf("MUTATEE:  after insert2 in fork of %d to %d\n", parent->getPid(), child->getPid());
       test2Child = child;
       test2Parent = parent;
    } else if (inTest == 4) {
       if (!child) return;	// skip prefork case

       // insert code into parent
       appImage = parent->getImage();
       assert(appImage);

       char *fn5 = "func4_3";
       if (NULL == appImage->findFunction(fn5, bpfv) || !bpfv.size()
	   || NULL == bpfv[0]){
	 fprintf(stderr, "    Unable to find function %s\n",fn5);
	 exit(1);
       }

       BPatch_function *func4_3_parent = bpfv[0];
       BPatch_funcCallExpr callExpr2(*func4_3_parent, nullArgs);

       bpfv.clear();
       char *fn6 = "func4_2";
       if (NULL == appImage->findFunction(fn6, bpfv) || !bpfv.size()
	   || NULL == bpfv[0]){
	 fprintf(stderr, "    Unable to find function %s\n",fn6);
	 exit(1);
       }

       BPatch_function *func4_2_parent = bpfv[0];
       BPatch_Vector<BPatch_point *> *point2 = func4_2_parent->findPoint(BPatch_exit);
       assert(point2);
       parent->insertSnippet(callExpr2, *point2);

       // code goes into child after in-exec in this test.

       test4Child = child;
    }
}

void exitFunc(BPatch_thread *thread, BPatch_exitType exit_type)
{
  dprintf("exitFunc called\n");
    // Read out the values of the variables.
    int exitCode = thread->getExitCode();

    assert(thread->terminationStatus() == exit_type);
    // Read out the values of the variables.
    if (inTest == 1) {
        if (exit_type == ExitedNormally) {
            if(thread->getPid() == exitCode) {
                if (verifyChildMemory(thread, "globalVariable1_1", 1000001)) {
                    printf("Passed test #1 (exit callback)\n");
                    passedTest[1] = true;
                } else {
                    printf("**Failed** test #1 (exit callback)\n");
                    printf("    verifyChildMemory failed\n");
                    passedTest[1] = false;
                }
            } else {
                printf("**Failed** test #1 (exit callback)\n");
                printf("    exit code = %d, was not equal to pid\n", exitCode);
                passedTest[1] = false;
            }
        } else if (exit_type == ExitedViaSignal) {
           printf("**Failed** test #1 (exit callback), exited via signal %d\n",
                   thread->getExitSignal());
            passedTest[1] = false;
        } else assert(false);
    } else if (inTest == 2) {
        static int exited = 0;
        exited++;
        if(exit_type == ExitedViaSignal) {
            printf("Failed test #2 (fork callback)\n");
            printf("    a process terminated via signal %d\n",
                   thread->getExitSignal());
            exited = 0;            
        } else if (thread->getPid() != exitCode) {
            printf("Failed test #2 (fork callback)\n");
            printf("    exit code was not equal to pid (%d != %d)\n", thread->getPid(), exitCode);            
            exited = 0;
        } else {
            dprintf("test #2, pid %d exited\n", exitCode);
            if ((test2Parent == thread) &&
                !verifyChildMemory(test2Parent, "globalVariable2_1", 2000002)) {
                failedTest[2] = true;
            }
            if ((test2Child == thread) &&
                !verifyChildMemory(test2Child, "globalVariable2_1", 2000003)) {
                failedTest[2] = true;
            }
            
            // See if all the processes are done
            if (exited == 2) {
                if (!failedTest[2]) {
                    printf("Passed test #2 (fork callback)\n");
                    passedTest[2] = true;
                } else {
                    printf("Failed test #2 (fork callback)\n");
                }
            }
        }
    } else if (inTest == 3) {
        // simple exec 
        if(exit_type == ExitedViaSignal) {
            printf("Failed test #3 (exec callback), exited via signal %d\n",
                   thread->getExitSignal());
        } else if (!verifyChildMemory(thread, "globalVariable3_1", 3000002)) {
            printf("Failed test #3 (exec callback)\n");
        } else {
            printf("Passed test #3 (exec callback)\n");
            passedTest[3] = true;
        }
    } else if (inTest == 4) {
        static int exited = 0;
        exited++;
        if (exit_type == ExitedViaSignal) {
            printf("Failed test #4 (fork callback)\n");
            printf("    process exited via signal %d\n",
                   thread->getExitSignal());
            failedTest[4] = true;            
        } else if (thread->getPid() != exitCode) {
            printf("Failed test #4 (fork callback)\n");
            printf("    exit code was not equal to pid\n");
            failedTest[4] = true;
        } else if (test4Parent == thread) {
            dprintf("test #4, pid %d exited\n", exitCode);
            if (!verifyChildMemory(test4Parent,"globalVariable4_1",4000002)){
                failedTest[4] = true;
            }
        } else if (test4Child == thread) {
            dprintf("test #4, pid %d exited\n", exitCode);
            if (!verifyChildMemory(test4Child, "globalVariable4_1", 4000003)) {
                failedTest[4] = true;
            }
        } else {
            // exit from unknown thread
            printf("Failed test #4 (fork callback)\n");
            printf("    exit from unknown pid = %d\n", exitCode);
            failedTest[4] = true;
        }
        // See if all the processes are done
        if (exited == 2) {
            if (!failedTest[4]) {
                printf("Passed test #4 (fork & exec)\n");
                passedTest[4] = true;
            } else {
                printf("Failed test #4 (fork & exec)\n");
            }
        }
    } else {
        printf("**Exit from unknown test case**\n");
    }
}

void execFunc(BPatch_thread *thread)
{
  BPatch_Vector<BPatch_function *> bpfv;

    if (inTest == 1 || inTest == 2) {
	printf("**Failed Test #%d\n", inTest);
	printf("    execCallback invoked, but exec was not called!\n");
    } else if (inTest == 3) {
	dprintf("in exec callback for %d\n", thread->getPid());

	// insert code into parent
	BPatch_Vector<BPatch_snippet *> nullArgs;
        BPatch_image *appImage = thread->getImage();
        assert(appImage);

	char *fn = "func3_2";
	if (NULL == appImage->findFunction(fn, bpfv) || !bpfv.size()
	    || NULL == bpfv[0]){
	  fprintf(stderr, "    Unable to find function %s\n",fn);
	  exit(1);
	}

        BPatch_function *func3_2_parent = bpfv[0];
        BPatch_funcCallExpr callExpr(*func3_2_parent, nullArgs);

	bpfv.clear();
	char *fn2 = "func3_1";
	if (NULL == appImage->findFunction(fn2, bpfv) || !bpfv.size()
	    || NULL == bpfv[0]){
	  fprintf(stderr, "    Unable to find function %s\n",fn2);
	  exit(1);
	}

	BPatch_function *func3_1_parent = bpfv[0];
	BPatch_Vector<BPatch_point *> *point = func3_1_parent->findPoint(BPatch_exit);

        assert(point);
        thread->insertSnippet(callExpr, *point);
	dprintf("%s[%d]:  MUTATEE: exec callback for %d, done with insert snippet\n", __FILE__, __LINE__, thread->getPid());
    } else if (inTest == 4) {
	dprintf("in exec callback for %d\n", thread->getPid());

        // insert code into child
	BPatch_Vector<BPatch_snippet *> nullArgs;
        BPatch_image *appImage = thread->getImage();
        assert(appImage);

	char *fn3 = "func4_4";
	if (NULL == appImage->findFunction(fn3, bpfv) || !bpfv.size()
	    || NULL == bpfv[0]){
	  fprintf(stderr, "    Unable to find function %s\n",fn3);
	  exit(1);
	}

	BPatch_function *func4_4_child = bpfv[0];
	BPatch_funcCallExpr callExpr1(*func4_4_child, nullArgs);
	
	bpfv.clear();
	char *fn4 = "func4_2";
	if (NULL == appImage->findFunction(fn4, bpfv) || !bpfv.size()
	    || NULL == bpfv[0]){
	  fprintf(stderr, "    Unable to find function %s\n",fn4);
	  exit(1);
	}

	BPatch_function *func4_2_child = bpfv[0];
	BPatch_Vector<BPatch_point *> *point1 = func4_2_child->findPoint(BPatch_exit);

	assert(point1);
        thread->insertSnippet(callExpr1, *point1);
    } else {
	printf("in exec callback for %d\n", thread->getPid());
    }
}

void errorFunc(BPatchErrorLevel level, int num, const char * const *params)
{
    if (num == 0) {
        // conditional reporting of warnings and informational messages
        if (errorPrint) {
            if (level == BPatchInfo)
              { if (errorPrint > 1) printf("%s\n", params[0]); }
            else
                printf("%s", params[0]);
        }
    } else {
        // reporting of actual errors
        char line[256];
        const char *msg = bpatch->getEnglishErrorString(num);
        bpatch->formatErrorString(line, sizeof(line), msg, params);
        
        if (num != expectError) {
            printf("Error #%d (level %d): %s\n", num, level, line);
        
            // We consider some errors fatal.
            if (num == 101) {
               exit(-1);
            }
        }
    }
}

void contAndWaitForAllThreads(BPatch_thread *appThread)
{
  dprintf("Thread %d is pointer %p\n", threadCount, appThread);
  mythreads[threadCount++] = appThread;
   appThread->continueExecution();

   while (1) {
      int i;
      dprintf("Checking %d threads for terminated status\n", threadCount);
      for (i=0; i < threadCount; i++) {
	if (!mythreads[i]->isTerminated()) {
	  dprintf("Thread %d is not terminated\n", i);
            break;
         }
      }

      // see if all exited
      if (i== threadCount) {
	dprintf("All threads terminated\n");
	break;
      }

      bpatch->waitForStatusChange();

      for (i=0; i < threadCount; i++) {
         if (mythreads[i]->isStopped()) {
	   dprintf("Thread %d marked stopped, continuing\n", i);
            mythreads[i]->continueExecution();
         }
      }
   }
   
   dprintf("All threads terminated, deleting\n");
   for (int i=0; i < threadCount; i++) {
     delete mythreads[i];
   }
   threadCount = 0;
}

void mutatorTest1(char *pathname)
{
#if defined(i386_unknown_nt4_0) \
 || defined(alpha_dec_osf4_0)

    printf("Skipping test #1 (exit callback)\n");
    printf("    not implemented on this platform\n");
    passedTest[1] = true;

#else
    int n = 0;
    const char *child_argv[MAX_TEST+5];
	
    dprintf("in mutatorTest1\n");

    inTest = 1;
    child_argv[n++] = pathname;
    if (debugPrint) child_argv[n++] = const_cast<char*>("-verbose");

    child_argv[n++] = const_cast<char*>("-run");
    child_argv[n++] = const_cast<char*>("1");
    child_argv[n] = NULL;

    // Start the mutatee
    printf("Starting \"%s\"\n", pathname);

    BPatch_thread *appThread = bpatch->createProcess(pathname, child_argv,NULL);
    dprintf("Test 1: using thread %p\n", appThread);
    if (appThread == NULL) {
	fprintf(stderr, "Unable to run test program.\n");
	exit(1);
    }

    contAndWaitForAllThreads(appThread);

    inTest = 0;
#endif
}


void mutatorTest2(char *pathname)
{
#if defined(i386_unknown_nt4_0) \
 || defined(alpha_dec_osf4_0)

    printf("Skipping test #2 (fork callback)\n");
    printf("    not implemented on this platform\n");
    passedTest[2] = true;

#else
    int n = 0;
    const char *child_argv[MAX_TEST+5];
	
    dprintf("\n\n\n\nin mutatorTest2\n");

    inTest = 2;
    child_argv[n++] = pathname;
    if (debugPrint) child_argv[n++] = const_cast<char*>("-verbose");

    child_argv[n++] = const_cast<char*>("-run");
    child_argv[n++] = const_cast<char*>("2");
    child_argv[n] = NULL;

    // Start the mutatee
    printf("Starting \"%s\"\n", pathname);

    BPatch_thread *appThread = bpatch->createProcess(pathname, child_argv,NULL);
    dprintf("Process %p created", appThread);
    if (appThread == NULL) {
	fprintf(stderr, "Unable to run test program.\n");
	exit(1);
    }

    contAndWaitForAllThreads(appThread);
    fprintf(stderr, "Finished with test2\n");
    inTest = 0;
#endif
}

void mutatorTest3(char *pathname)
{
#if defined(i386_unknown_nt4_0) \
 || defined(alpha_dec_osf4_0)

    printf("Skipping test #3 (exec callback)\n");
    printf("    not implemented on this platform\n");
    passedTest[3] = true;

#else
    int n = 0;
    const char *child_argv[MAX_TEST+5];
	
    dprintf("in mutatorTest3\n");

    inTest = 3;
    child_argv[n++] = pathname;
    if (debugPrint) child_argv[n++] = const_cast<char*>("-verbose");

    child_argv[n++] = const_cast<char*>("-run");
    child_argv[n++] = const_cast<char*>("3");
    child_argv[n] = NULL;

    // Start the mutatee
    printf("Starting \"%s\"\n", pathname);

    BPatch_thread *appThread = bpatch->createProcess(pathname, child_argv,NULL);
    if (appThread == NULL) {
	fprintf(stderr, "Unable to run test program.\n");
	exit(1);
    }

    contAndWaitForAllThreads(appThread);

    inTest = 0;
#endif
}

void mutatorTest4(char *pathname)
{
#if defined(i386_unknown_nt4_0) \
 || defined(alpha_dec_osf4_0)

    printf("Skipping test #4 (fork & exec)\n");
    printf("    not implemented on this platform\n");
    passedTest[4] = true;

#else
    int n = 0;
    const char *child_argv[MAX_TEST+5];
	
    dprintf("in mutatorTest4\n");

    inTest = 4;
    child_argv[n++] = pathname;
    if (debugPrint) child_argv[n++] = const_cast<char*>("-verbose");

    child_argv[n++] = const_cast<char*>("-run");
    child_argv[n++] = const_cast<char*>("4");
    child_argv[n] = NULL;

    // Start the mutatee
    printf("Starting \"%s\"\n", pathname);

    test4Parent = bpatch->createProcess(pathname, child_argv,NULL);
    if (test4Parent == NULL) {
	fprintf(stderr, "Unable to run test program.\n");
	exit(1);
    }

    contAndWaitForAllThreads(test4Parent);

    inTest = 0;
#endif
}

void mutatorMAIN(char *pathname)
{
    // Create an instance of the BPatch library
    bpatch = new BPatch;

    // Force functions to be relocated
    if (forceRelocation) {
      bpatch->setForcedRelocation_NP(true);
    }

    bpatch->setTrampRecursive(true);
    // Register a callback function that prints any error messages
    bpatch->registerErrorCallback(errorFunc);
    bpatch->registerPreForkCallback(forkFunc);
    bpatch->registerPostForkCallback(forkFunc);
    bpatch->registerExecCallback(execFunc);
    bpatch->registerExitCallback(exitFunc);

    if (runTest[1]) mutatorTest1(pathname);
    if (runTest[2]) mutatorTest2(pathname);
    if (runTest[3]) mutatorTest3(pathname);
    if (runTest[4]) mutatorTest4(pathname);
    unsigned int testsFailed = 0;
    for (unsigned int i=1; i <= MAX_TEST; i++) {
        if (runTest[i] && !passedTest[i]) testsFailed++;
    }

    if (!testsFailed) {
        if (runAllTests) {
            printf("All tests passed\n");
        } else {
            printf("All requested tests passed\n");
        }
    }
}

//
// main - decide our role and call the correct "main"
//
int
main(unsigned int argc, char *argv[])
{
    unsigned int i;
    bool ABI_32=false;
    char mutateeName[128];
    char libRTname[256];

    strcpy(mutateeName,mutateeNameRoot);
    libRTname[0]='\0';

    if (!getenv("DYNINSTAPI_RT_LIB")) {
	 fprintf(stderr,"Environment variable DYNINSTAPI_RT_LIB undefined:\n"
#if defined(i386_unknown_nt4_0)
		 "    using standard search strategy for libdyninstAPI_RT.dll\n");
#else
	         "    set it to the full pathname of libdyninstAPI_RT\n");   
         exit(-1);
#endif
    } else
         strcpy((char *)libRTname, (char *)getenv("DYNINSTAPI_RT_LIB"));

    updateSearchPaths(argv[0]);

    // by default run all tests
    for (i=1; i <= MAX_TEST; i++) {
        runTest[i] = true;
        passedTest[i] = false;
    }

    for (i=1; i < argc; i++) {
        if (strncmp(argv[i], "-v+", 3) == 0)    errorPrint++;
        if (strncmp(argv[i], "-v++", 4) == 0)   errorPrint++;
	if (strncmp(argv[i], "-verbose", 2) == 0) {
	    debugPrint = 1;
	} else if (!strcmp(argv[i], "-V")) {
            if (libRTname[0]) 
                fprintf (stdout, "DYNINSTAPI_RT_LIB=%s\n", libRTname);
            fflush(stdout);
	} else if (!strcmp(argv[i], "-skip")) {
	    unsigned int j;
	    runAllTests = false;
            for (j=i+1; j < argc; j++) {
                unsigned int testId;
                if ((testId = atoi(argv[j]))) {
                    if ((testId > 0) && (testId <= MAX_TEST)) {
                        runTest[testId] = false;
                    } else {
                        printf("invalid test %d requested\n", testId);
                        exit(-1);
                    }
                } else {
                    // end of test list
		    break;
                }
            }
            i=j-1;
	} else if (!strcmp(argv[i], "-run")) {
	    unsigned int j;
	    runAllTests = false;
            for (j=0; j <= MAX_TEST; j++) runTest[j] = false;
            for (j=i+1; j < argc; j++) {
                unsigned int testId;
                if ((testId = atoi(argv[j]))) {
                    if ((testId > 0) && (testId <= MAX_TEST)) {
                        runTest[testId] = true;
                    } else {
                        printf("invalid test %d requested\n", testId);
                        exit(-1);
                    }
                } else {
                    // end of test list
		    break;
                }
            }
            i=j-1;
	} else if (!strcmp(argv[i], "-mutatee")) {
	    i++;
            if (*argv[i]=='_')
                strcat(mutateeName,argv[i]);
            else
                strcpy(mutateeName,argv[i]);
#if defined(i386_unknown_nt4_0) \
 || defined(i386_unknown_linux2_0) \
 || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */ \
 || defined(sparc_sun_solaris2_4) \
 || defined(ia64_unknown_linux2_4)
	} else if (!strcmp(argv[i], "-relocate")) {
            forceRelocation = true;
#endif
#if defined(x86_64_unknown_linux2_4)
	} else if (!strcmp(argv[i], "-m32")) {
	    ABI_32=true;
#endif
	} else {
	    fprintf(stderr, "Usage: test4 "
		    "[-V] [-verbose] "
#if defined(mips_sgi_irix6_4)
		    "[-n32] "
#endif
                    "[-mutatee <test4a.mutatee>] "
		    "[-run <test#> <test#> ...] "
		    "[-skip <test#> <test#> ...]\n");
            fprintf(stderr, "%d subtests\n", MAX_TEST);
	    exit(-1);
	}
    }

    if (!runAllTests) {
        printf("Running Tests: ");
	for (unsigned int j=1; j <= MAX_TEST; j++) {
	    if (runTest[j]) printf("%d ", j);
	}
	printf("\n");
    }

    // patch up the default compiler in mutatee name (if necessary)
    if (!strstr(mutateeName, "_"))
#if defined(i386_unknown_nt4_0)
        strcat(mutateeName,"_VC");
#else
        strcat(mutateeName,"_gcc");
#endif
    if (ABI_32 || strstr(mutateeName,"_m32")) {
        // patch up file names based on alternate ABI (as necessary)
        if (!strstr(mutateeName, "_m32")) strcat(mutateeName,"_m32");
    }
    // patch up the platform-specific filename extensions
#if defined(i386_unknown_nt4_0)
    if (!strstr(mutateeName, ".exe")) strcat(mutateeName,".exe");
#endif

    mutatorMAIN(mutateeName);

    return 0;
}
