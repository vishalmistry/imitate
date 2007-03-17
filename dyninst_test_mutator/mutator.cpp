#include <stdio.h>
#include <pthread.h>
#include "BPatch.h"
#include "BPatch_function.h"
#include "BPatch_edge.h"

BPatch bpatch;

int main(int argc, char *argv[])
{
	if (argc < 3) {
 		fprintf(stderr, "Usage: %s <prog/all> prog_filename prog_aruments\n", argv[0]);
		return 3;
	}

	if (strcmp(argv[1], "prog") != 0 && strcmp(argv[1], "all"))
	{
		fprintf(stderr, "Options for patch selection are 'progonly' or 'all'\n");
		return 3;
	}

	int patchall = strcmp(argv[1], "all") != 0;

	// Create process
	BPatch_process *appProc = bpatch.processCreate(argv[2], (const char**) &(argv[3]));

    // Load pthread into the process...
    appProc->loadLibrary("libpthread.so.0");
	
	// Get the process image	
	BPatch_image *appImage = appProc->getImage();

	// Find all the instrumentable procedures
	BPatch_Vector<BPatch_function*> *functions = appImage->getProcedures(); 	

	// Allocate counter
	BPatch_variableExpr *intCounter = appProc->malloc(*appImage->findType("int"));

    printf("intCounter address: %x\n PID: %d\n", intCounter->getBaseAddr(), appProc->getPid());
    fflush(stdout);

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

	// Create 'increment counter' snippet
	BPatch_arithExpr addOneToCounter(BPatch_assign, *intCounter,
		BPatch_arithExpr(BPatch_plus, *intCounter, BPatch_constExpr(1)));

    BPatch_Vector<BPatch_snippet*> snippet;
    snippet.push_back(&mutexLockCall);
    snippet.push_back(&addOneToCounter);
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
		if (patchall && strcmp(modname, "DEFAULT_MODULE") != 0) continue;

		printf("Patching function: '%s' (%s)", name, modname);

		// Get the control flow graph for the procedure
		BPatch_flowGraph *graph = (*functions)[i]->getCFG();

		// Find the loops
		BPatch_Vector<BPatch_basicBlockLoop*> *loops = new BPatch_Vector<BPatch_basicBlockLoop*>();
		graph->getLoops(*loops);
	
		// Patch the loop back-edges
		for(int j = 0; j < loops->size(); j++)
		{
			appProc->insertSnippet(addOneAtomic, *((*loops)[j]->getBackEdge()->getPoint()));
			printf(".", (int) (*loops)[j]->getBackEdge()->getPoint()->getAddress());
		}
		printf("\n");

		// Free the loops found
		delete(loops);
	}

	appProc->finalizeInsertionSet(false);	

	// Clear up memory used to store the name
	free(name);
	free(modname);

	// Patch main() function to print out no of back branches at the end
	// Find function
	BPatch_Vector<BPatch_function*> mainFuncs;
		appImage->findFunction("exit", mainFuncs);
	if (mainFuncs.size() == 0)
		appImage->findFunction("_exit", mainFuncs);
	if (mainFuncs.size() == 0)
		appImage->findFunction("__exit", mainFuncs);

	if(mainFuncs.size() == 0)
	{
		fprintf(stderr, "Could not find exit() function");
		return 2;
	}

	// Get exit() exit point
	BPatch_Vector<BPatch_point*> *mainPoints = mainFuncs[0]->findPoint(BPatch_entry);

	// Build printf() call:
	//	printf("Total Total Back-branches: %d\n", counter);

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

	// Build arguments to printf()
	BPatch_Vector<BPatch_snippet*> printfArgs;
	BPatch_constExpr formatString("Total Back-branches: %d\n");

	printfArgs.push_back(&formatString);
	printfArgs.push_back(intCounter);

	// Build call to printf()
	BPatch_funcCallExpr printfCall(*printfFuncs[0], printfArgs);

	// Patch into main()
	appProc->insertSnippet(printfCall, *mainPoints);

	// Continue mutatee...
	appProc->continueExecution();

	// Wait for mutatee to finish
	while (!appProc->isTerminated())
	{
		bpatch.waitForStatusChange();
	}
	
	printf("Done.\n");
	return 0;
}
