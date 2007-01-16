#include <stdio.h>
#include <fcntl.h>
#include "BPatch.h"
#include "BPatch_Vector.h"
#include "BPatch_thread.h"
#include "BPatch_function.h"

BPatch bpatch;

int main(int argc, char *argv[])
{
  int pid;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s prog_filename pid log_filename\n",argv[0]);
       exit(1);
  }

  pid = atoi(argv[2]);

  // Attach to the program
  BPatch_thread *appThread = bpatch.attachProcess(argv[1], pid);

  // Read the program's image and get an associated image object
  BPatch_image *appImage = appThread->getImage();
  BPatch_Vector<BPatch_function*> writeFuncs;

  // Try different variations of write depending on platform
  appImage->findFunction("__write_nocancel", writeFuncs);
  if (writeFuncs.size() == 0)
    appImage->findFunction("_write", writeFuncs);
  if (writeFuncs.size() == 0)
    appImage->findFunction("write", writeFuncs);
  if (writeFuncs.size() == 0)
    appImage->findFunction("__write", writeFuncs);

  if(writeFuncs.size() == 0)
      return -1;

  // Find the entry point to the procedure "write"
  BPatch_Vector<BPatch_point*> *points = writeFuncs[0]->findPoint(BPatch_entry);

  if ((*points).size() == 0) {
    fprintf(stderr, "Unable to find entry point to \"write.\"\n");
    exit(1);
  }

  // Generate code that opens the file the first time it is called.
  // The code to be generate is:
  // if (!flagVar) {
  //   fd = open(argv[3], O_WRONLY|O_CREAT, 0666);
  //   flagVar = 1;
  // }

  // (1) Find the open function
  BPatch_Vector<BPatch_function*> openFuncs;

  // Try 64-bit open first
  appImage->findFunction("open64", openFuncs);
  if (openFuncs.size() == 0)
    appImage->findFunction("open", openFuncs);
  if (openFuncs.size() == 0)
    appImage->findFunction("__open", openFuncs);
  if (openFuncs.size() == 0) {
    fprintf(stderr, "Unable to find \"open\" function\n");
    exit(1);
  }

  // (2) Allocate a vector of snippets for the parameters to open
  BPatch_Vector<BPatch_snippet *> openArgs;

  // (3) Create a string constant expression from argv[3]
  BPatch_constExpr fileName(argv[3]);

  // (4) Create two more constant expressions _WRONLY|O_CREAT and 0666
  BPatch_constExpr fileFlags(O_WRONLY|O_CREAT);
  BPatch_constExpr fileMode(0666);

  // (5) Push 3 && 4 onto the list from step 2
  openArgs.push_back(&fileName);
  openArgs.push_back(&fileFlags);
  openArgs.push_back(&fileMode);

  // (6) create a procedure call using function found at 1 and
  //         parameters from step 5.
  BPatch_funcCallExpr openCall(*openFuncs[0], openArgs);
  void *openFD = appThread->oneTimeCode(openCall);

  // (7) allocate a variable to hold the open file descriptor
  BPatch_variableExpr *fdVar =
    appThread->malloc(*appImage->findType("int"));

  // (8) create assignment statement of variable from step 7 to return
  //     value from step 6.
  BPatch_arithExpr openFile(BPatch_assign, *fdVar, openCall);

  // (9) Find the integer type, and then allocate a variable
  //     of this type to be used as a flag to indicate if the
  //     open call was made on a previous call to write.
  BPatch_variableExpr *flagVar =
    appThread->malloc(*appImage->findType("int"));

  // Declare a snippet vector to hold the list of items
  BPatch_Vector<BPatch_snippet *> initStatements;

  // (10) flagVar = 1;
  BPatch_arithExpr setFlag(BPatch_assign, *flagVar, BPatch_constExpr(1));

  // (11) make a sequence of the open and the assignment statements
  initStatements.push_back(&openFile);
  initStatements.push_back(&setFlag);
  BPatch_sequence initSequence(initStatements);

  // (12) create expression (flagVar == 1)
  BPatch_boolExpr testFlag(BPatch_eq, *flagVar, BPatch_constExpr(0));

  // (13) use expression #12 and statement #11 to produce if-statement
  BPatch_ifExpr initIfNeeded(testFlag, initSequence);

  // Generate the code that copies all writes to file descriptor 1
  // to our log file.
  // Call write with the same data but for our file descriptor
  // The C code we generate is:
  //   if (parameter[0] == 1) {
  //     write(fd, parameter[1], parameter[2])
  //   }
 
  // Find the write function call
  //   BPatch_Vector<BPatch_function *>writeFuncs;
  //   appImage->findFunction("write", writeFuncs);
  // Build up a parameter list with the items:
  //   1) The file description of our log file
  //   2) First parameter to the original function
  //   3) Second parameter to the original function
  BPatch_Vector<BPatch_snippet *> writeArgs;
  BPatch_paramExpr paramBuf(1);
  BPatch_paramExpr paramNbyte(2);
  BPatch_constExpr openFD_snippet(openFD);
  writeArgs.push_back(&openFD_snippet);
  writeArgs.push_back(&paramBuf);
  writeArgs.push_back(&paramNbyte);

  // Create a function call snippet write(fd, parameter[1], parameter[2])
  BPatch_funcCallExpr writeCall(*writeFuncs[0], writeArgs);

  // Insert the code into the thread.
  appThread->insertSnippet(writeCall, *points);

  // continue execution of the mutatee
  appThread->continueExecution();

  // wait for mutatee to terminate and allow Dyninst to handle events
  while (!appThread->isTerminated())
    bpatch.waitForStatusChange();

  printf("Done.\n");

  return 0;
}
