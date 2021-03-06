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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <iostream.h>
#include <fstream.h>
#include <limits.h>
#include <pthread.h>
#include <tcl.h>
#include <tk.h>

#include "common/h/Vector.h"
#include "common/src/Dictionary.C"
#include "BPatch_Set.h"

#include "common/h/Types.h"
#include "common/h/String.h"
#include "dyninstAPI/src/LineInformation.h"

#include <CCcommon.h>
#include <FCAllBlocks.h>
#include <FCUseDominator.h>
#include <CodeCoverage.h>

BPatch_function* exitHandle = NULL;
BPatch_Vector<unsigned short> frequencyCode;
BPatch_Vector<unsigned short> frequencyLine;

/** a linked list definition of functions to be used in hash structure */
class BPFunctionList {
public:
        BPatch_function* f;
        BPatch_module* m;
        BPFunctionList* n;

        BPFunctionList(BPatch_function* argf,BPatch_module* argm) :
                f(argf),m(argm),n(NULL){}
        BPFunctionList(BPatch_function* argf,BPatch_module* argm,
                       BPFunctionList* argn) : f(argf),m(argm),n(argn){}
};

/** mapping from function name to linked list of functions with the same name */
dictionary_hash<pdstring,BPFunctionList*>* allFunctionsHash = NULL;

dictionary_hash<pdstring,FunctionCoverage*>* allCoverageHash = NULL;

/** static initialization of the global code coverage object used
  * by interval call backs
  */
CodeCoverage* CodeCoverage::globalObject = NULL;
unsigned short CodeCoverage::fileCount = 0;
unsigned short* CodeCoverage::fileStartIndex = NULL;
unsigned short* CodeCoverage::fileLineCount = NULL;
FileLineCoverage** CodeCoverage::fileLineCoverage = NULL;

/** constructor */
CodeCoverage::CodeCoverage()
	: appThread(NULL),appImage(NULL),coverageFileName(NULL),
	  deletionInterval(0),appModules(NULL),
	  instrumentedFunctions(NULL),instrumentedFunctionCount(0),
	  useDominator(false),globalInterp(NULL),statusBarName(NULL),
	  whichInterval(0),totalDeletions(0),totalCoveredLines(0),
	  tclStatusChanged(false)
{
	pthread_mutex_init(&updateLock,NULL);
	pthread_mutex_init(&statusUpdateLock,NULL);
}

/** constructor */
CodeCoverage::~CodeCoverage()
{
	delete[] coverageFileName;
	delete appModules;
	for(int i=0;i<instrumentedFunctionCount;i++)
		delete instrumentedFunctions[i];
	delete[] instrumentedFunctions;
	delete FILE_EXTENSION;
	pthread_mutex_destroy(&updateLock);
	pthread_mutex_destroy(&statusUpdateLock);
}

/** error printing function that overrides dyninst default 
  * function
  */
void codeCoverageError(BPatchErrorLevel /* level */,
                       int /* num */, const char * const * /* params */)
{ }

/** this method initializes the necessary data structures and
  * creates a map from string name to the linked list of function
  * records to be used later to access function faster
  */
int CodeCoverage::initialize(const char* mutatee[],unsigned short interval,
			     bool dominatorInfo,const char* suffix)
{
	deletionInterval = interval;
	useDominator = dominatorInfo;
	FILE_EXTENSION = new char[strlen(suffix)+1];
	strcpy(FILE_EXTENSION,suffix);

	coverageFileName = new char[strlen(mutatee[0])+strlen(FILE_EXTENSION)+1];
	strcpy(coverageFileName,mutatee[0]);
	strcat(coverageFileName,FILE_EXTENSION);

	registerErrorCallback(codeCoverageError);

	/** create the process */
	appThread = bPatch.createProcess(mutatee[0],mutatee);
	if(!appThread)
		return errorPrint(Error_ThreadCreate);

	/** get the image */
	appImage = appThread->getImage();
	if(!appImage)
		return errorPrint(Error_ImageCreate);

	allFunctionsHash = 
		new dictionary_hash<pdstring,BPFunctionList*>(pdstring::hash);

	if(!allFunctionsHash)
		return errorPrint(Error_HashCreate);

	/** get the modules in the image */
	appModules = appImage->getModules();

	if(!appModules)
		return errorPrint(Error_ModuleCreate);
	
	/** for each module in the image get the functions and
	  * insert them into the map
	  */
	for(unsigned int i=0;i<appModules->size();i++){
		BPatch_module* m = (*appModules)[i];
		char mName[1024];
		m->getName(mName,1023);
		BPatch_Vector<BPatch_function*>* fs = m->getProcedures();
		for(unsigned int j=0;j<fs->size();j++){
			BPatch_function* f = (*fs)[j];
			char fName[1023];
			f->getMangledName(fName,1023); fName[1023] = '\0';
			if(allFunctionsHash->defines(pdstring(fName))){
				/** if already there add to the front */
				BPFunctionList* fl = (*allFunctionsHash)[fName];
				(*allFunctionsHash)[pdstring(fName)] = 
					new BPFunctionList(f,m,fl);
			}
			else
				/** create a new linked list */
				(*allFunctionsHash)[pdstring(fName)] = 
					new BPFunctionList(f,m);
		}
		delete fs;
	}

	if(allFunctionsHash->defines(pdstring("_exithandle"))){
		BPFunctionList* fl = (*allFunctionsHash)[pdstring("_exithandle")];
		exitHandle = fl->f;
	}
				
	/** set the base trampoline deletion to true to delete
	  * base trampolines when there is no more instrumentation code
	  * at the point
	  */
	bPatch.setBaseTrampDeletion(true);

	return Error_OK;
}

/** method that validates whether the function has source line
  * information available. To do that, the records from the source
  * line information stab is compared with the functions with the same
  * name and its properties (if there are more than 1 possible functions
  * with the same name 
  */
BPatch_function* CodeCoverage::validateFunction(const char* funcN,
						unsigned long min)
{

	BPatch_function* currFunc = NULL;
	
	/** get the possible functions with the same name */
	BPFunctionList* possibleFunctions = NULL;
	if(allFunctionsHash->defines(pdstring(funcN)))
		possibleFunctions = (*allFunctionsHash)[pdstring(funcN)];

	if(!possibleFunctions)
		return NULL;

	/** for each possible function compare the source code line info
	  * record with the properties of the function. If matches
	  * then terminate otherwise continue
	  */
	for(;possibleFunctions;possibleFunctions=possibleFunctions->n){
		Address fb=(Address)(possibleFunctions->f->getBaseAddr());
		Address fe=fb + possibleFunctions->f->getSize();
		if((fb <= min) && (min <= fe)){
			currFunc = possibleFunctions->f;
			break;
		}
	}

	if(!currFunc)
		return NULL;

	return currFunc;
}

/** creates a function coverage object according to the 
  * the nature of instrumentation, tthat is whether all basic block
  * instrumentation will be used or dominator tree information
  * will be used 
  */
FunctionCoverage* CodeCoverage::newFunctionCoverage(BPatch_function* f,
				 const char* funcN,FileLineCoverage* flc)
{
	FunctionCoverage* ret = NULL;
	if(useDominator)
		ret = new FCUseDominator(f,appThread,appImage,funcN);
	else
		ret = new FCAllBlocks(f,appThread,appImage,funcN);

	ret->addSourceFile(flc);
	flc->setOwner(ret);

	return ret;
}

void CodeCoverage::createFileStructure(){

	unsigned short i = 0, j = 0;

	int sourceObjectCount = 0;
	for(i=0;i<instrumentedFunctionCount;i++){
		FunctionCoverage* fc = instrumentedFunctions[i];
		for(j=0;j<fc->sourceFileLinesCount;j++)
			sourceObjectCount++;
	}

	fileLineCoverage = new FileLineCoverage*[sourceObjectCount + 1];
	fileLineCoverage[sourceObjectCount] = NULL;

	sourceObjectCount = 0;
	for(i=0;i<instrumentedFunctionCount;i++){
		FunctionCoverage* fc = instrumentedFunctions[i];
		for(j=0;j<fc->sourceFileLinesCount;j++)
			fileLineCoverage[sourceObjectCount++] = fc->sourceFileLines[j];
	}

	qsort((void*)fileLineCoverage,
	      sourceObjectCount,sizeof(FileLineCoverage*),
	      FLSortByFileName);

	fileCount = 0;

	const char* tmp = "what can it be";
	for(i=0;i<sourceObjectCount;i++)
		if(strcmp(tmp,fileLineCoverage[i]->fileName)){
			tmp = fileLineCoverage[i]->fileName;
			fileCount++;
		}

	if(!fileCount)
		return;

	tmp = "can not be";
	fileStartIndex = new unsigned short[fileCount];
	fileLineCount = new unsigned short[fileCount];
	for(i=0,j=0;i<sourceObjectCount;i++)
		if(strcmp(tmp,fileLineCoverage[i]->fileName)){
			fileStartIndex[j] = i;
			fileLineCount[j] = fileLineCoverage[i]->lineCount;
			tmp = fileLineCoverage[i]->fileName;
			j++;
		}
		else 
			fileLineCount[j-1] += fileLineCoverage[i]->lineCount;

	for(i=0;i<fileCount;i++)
		cout << "information: file "
		     << fileLineCoverage[fileStartIndex[i]]->fileName
		     << " will be analyzed..." << endl;
}

/** method to select the functions whose source line information is available
  * and whose data is stored in dyninst. It goes over the line information 
  * strucute elements and for each source file and function it check whether
  * the source line info record matches the properties of the function in dyninst
  * If they match it is added to be instrumented. This method also creates and
  * initializes the data structures that will be used for function coverage
  */
int CodeCoverage::selectFunctions() {
	allCoverageHash = new dictionary_hash< pdstring, FunctionCoverage * >(pdstring::hash);

	for( unsigned int i = 0; i < appModules->size(); ++i ) {
		BPatch_module * currentModule = (* appModules)[i];

		/* Skip the synthetic modules. */
		char currentModuleName[1024];
		char currentFunctionName[1024];
		currentModule->getName( currentModuleName, 1023 );

		if(	strcmp( currentModuleName, "DEFAULT_MODULE" ) == 0
			|| strcmp( currentModuleName, "DYN_MODULE" ) == 0
			|| strcmp( currentModuleName, "LIBRARY_MODULE" ) == 0 ) {
			continue;
			}

		LineInformation & lineInformation = currentModule->getLineInformation();
		for(	LineInformation::const_iterator iter = lineInformation.begin();
				iter != lineInformation.end();
				++ iter ) {
			BPatch_function * currentFunction = appThread->findFunctionByAddr( (void *)(iter->first.first) );
			if( currentFunction == NULL ) {
				fprintf( stderr, "%s[%d]: Unable to locate function in line information at address 0x%lx\n", __FILE__, __LINE__, iter->first.first );
				continue;
				}
			currentFunction->getName( currentFunctionName, 1023 );
			pdstring pdCurrentFunctionName( currentFunctionName );
			
			/* Generate the flc. */
			FileLineCoverage * flc = new FileLineCoverage( iter->second.first );

			/* Tikir: All line number should be changed to be unsigned ints. */
			BPatch_Set< unsigned short > lines;
			lines += (unsigned short)(iter->second.second);
			flc->initializeLines( lines );

			/* Add FLC to existing FC or create new FC with it, and register in allCoverageHash. */
			FunctionCoverage * fc = NULL;
			if( allCoverageHash->defines( pdCurrentFunctionName ) ) {
				fc = allCoverageHash->get( pdCurrentFunctionName );
				fc->addSourceFile( flc );
				flc->setOwner( fc );
				}
			else {
				fc = newFunctionCoverage( currentFunction, currentFunctionName, flc );
				allCoverageHash->set( pdCurrentFunctionName, fc );
				}

			} /* end iteration over line information */
		} /* end iteration over modules */

	if( allCoverageHash->size() == 0 ) {
		return errorPrint( Error_NoFunctionsToCover );
		}

	/** creates the necessary data structures and initializes them */
	instrumentedFunctionCount = allCoverageHash->size();
	instrumentedFunctions = new FunctionCoverage * [ instrumentedFunctionCount ];
	
	dictionary_hash< pdstring, FunctionCoverage * >::const_iterator iter = allCoverageHash->begin();
	for( int j = 0; iter != allCoverageHash->end() && j < instrumentedFunctionCount; ++iter, ++j ) {
		instrumentedFunctions[j] = * iter;
		}

	cout	<< "information: " << instrumentedFunctionCount
			<< " functions are selected to be instrumented..." << endl;

	/** sort the function coverage objects according to the name of the functions */
	qsort(	(void *)instrumentedFunctions, instrumentedFunctionCount,
			sizeof( FunctionCoverage * ), FCSortByFileName );

	createFileStructure();
	return Error_OK;
	} /* end CodeCoverage::selectFunctions() */

/** method to do initial instrumentation */
int CodeCoverage::instrumentInitial(){
	return Error_OK;
}

/** method to run the mutatee */
int CodeCoverage::run(){
	return Error_OK;
}

/** method to instrument exit handle to detect the
  * termination of the mutatee
  */
int CodeCoverage::instrumentExitHandle()
{
	BPatch_breakPointExpr breakExpr;
        BPatch_Vector<BPatch_point*>* breakPoints = NULL;
        BPatchSnippetHandle* ret = NULL;

	/** _exithandle is the exit function to be called for sparc*/
        breakPoints = exitHandle->findPoint(BPatch_entry);

	if(!breakPoints)
		return errorPrint(Error_ProcedurePoint,"Entry to _exithandle");

	ret = appThread->insertSnippet(breakExpr,*breakPoints,
				       BPatch_callBefore,BPatch_lastSnippet);

	if(!ret)
		return errorPrint(Error_InsertSnippet,"Breakpoint to _exithandle");

	delete breakPoints;

	return Error_OK;
}

/** method to print the error codes for this class */
int CodeCoverage::errorPrint(int code,char* text)
{
	cerr << "Error(" << code << ") : ";

	switch(code){
		case Error_FileOpen:
			cerr << "File can not be opened. ";
			break;
		case Error_ThreadCreate:
			cerr << "The bpatch thread can not be created. ";
			break;
		case Error_ImageCreate:
			cerr << "The bpatch image can not be created. ";
			break;
		case Error_HashCreate:
			cerr << "Buffer for possible intrumentable functions can not be created. ";
			break;
		case Error_ModuleCreate:
			cerr << "Modules in the image can not be created. ";
			break;
		case Error_NoFunctionsToCover:
			cerr << "There are no functions/line information to test for source coverage. ";
			break;
		case Error_DeletionInterval:
			cerr << "An error occurred in deletion interval. ";
			break;
		case Error_PrintResult:
			cerr << "Coverage results can not be printed. ";
			break;
		case Error_FileFormat:
			cerr << "Coverage file is not in valid format. ";
			break;
		default: cerr << "Unrecognized error!!!!";
	}

	if(text)
		cerr << endl << "\t[ " << text << " ]";

	cerr << endl;

	return code;
}

void CodeCoverage::terminate(){
	if(appThread && !appThread->isTerminated())
		appThread->terminateExecution();
}

/** method to be called during the deletion intervals */
int CodeCoverage::deletionIntervalCallback(){
	return Error_OK;
}

/** function that is used to sort the function coverage objects according
  * to the names of the functions
  */
int FLSortByFileName(const void* arg1,const void* arg2){
	FileLineCoverage* e1 = *((FileLineCoverage* const *)arg1);
	FileLineCoverage* e2 = *((FileLineCoverage* const *)arg2);

	int check = strcmp(e1->fileName,
			   e2->fileName);
	if(check > 0)
		return 1;
	if(check < 0)
		return -1;

	check = strcmp(e1->owner->functionName,
		       e2->owner->functionName);
	if(check > 0)
		return 1;
	if(check < 0)
		return -1;
	return 0;
}

/** function that is used to sort the function coverage objects according
  * to the names of the functions
  */
int FCSortByFileName(const void* arg1,const void* arg2){
	FunctionCoverage* e1 = *((FunctionCoverage* const *)arg1);
	FunctionCoverage* e2 = *((FunctionCoverage* const *)arg2);

	int check = strcmp(e1->sourceFileLines[0]->fileName,
			   e2->sourceFileLines[0]->fileName);
	if(check > 0)
		return 1;
	if(check < 0)
		return -1;

	check = strcmp(e1->functionName,
		       e2->functionName);
	if(check > 0)
		return 1;
	if(check < 0)
		return -1;
	return 0;
}

/** method to print the coverage results to a binary file.
  * it iterates over the function coverage objects and prints 
  * the results for each of them.
  */
int CodeCoverage::printCoverageInformation(){

	if(globalInterp && statusBarName){
		pthread_mutex_lock(&statusUpdateLock);
		tclStatusChanged = true;
		/*
		sprintf(tclStatusBuffer,"%s configure -text \
			\"Dumping coverage results to the binary file...\"",
			statusBarName);
		*/
		pthread_mutex_unlock(&statusUpdateLock);
	}

	/** update the execution counts for the last time */
	updateFCObjectInfo();

	/** create the coverage results file */
	coverageFile.open(coverageFileName,std::ios::out);
	if(!coverageFile)
		return errorPrint(Error_FileOpen,coverageFileName);

	/** write the unique identifier for the file format */
	char* ccid = "Dyncov-1.0";
	coverageFile.write(ccid,10);

	/** for each function coverage print the results */
	for(int i=0;i<instrumentedFunctionCount;i++)
		instrumentedFunctions[i]->printCoverageInformation(
					coverageFile);

	/** print the termination flag */
	unsigned tmp_u = 0;
	coverageFile.write((char*)&tmp_u,sizeof(unsigned));

	/** close the output file */
	coverageFile.close();

	return Error_OK;
}

/** method that updates execution counts of each basic block 
  * instrumented going over the function coverage objects
  */
int CodeCoverage::updateFCObjectInfo(){

	pthread_mutex_lock(&updateLock);

        for(int i=0;i<instrumentedFunctionCount;i++)
             if(isInstrumented(i))
                instrumentedFunctions[i]->updateExecutionCounts();

	pthread_mutex_unlock(&updateLock);

        return Error_OK;
}

/** method that returns whether a function is instrumented or not */
bool CodeCoverage::isInstrumented(int i){
        return true || i;
}

/** method to register the error function for dyninst error call back */
BPatchErrorCallback
CodeCoverage::registerErrorCallback(BPatchErrorCallback f){
	return bPatch.registerErrorCallback(f);
}

void CodeCoverage::addTclTkFrequency(){
	if(deletionInterval && globalInterp && statusBarName){
		pthread_mutex_lock(&updateLock);
		frequencyCode.push_back(totalDeletions);
		frequencyLine.push_back(totalCoveredLines);
		pthread_mutex_unlock(&updateLock);
	}
}

void CodeCoverage::getTclTkExecutedLines(ofstream& file){
   if(deletionInterval || appThread->isTerminated()) {

	if(globalInterp && statusBarName){
		pthread_mutex_lock(&statusUpdateLock);
		tclStatusChanged = true;
		sprintf(tclStatusBuffer,"%s configure -text \
			\"Updating executed line information...\"",
			statusBarName);
		pthread_mutex_unlock(&statusUpdateLock);
	}

	pthread_mutex_lock(&updateLock);

	for(unsigned int i=0;i<fileCount;i++){
		file << "set globalExecutionMap(" << i << ") \\" << endl;
		file << "\t[list \\" << endl
		     << "\t\t[list \\" << endl;

		unsigned short index = fileStartIndex[i];
		const char* fileName = fileLineCoverage[index]->fileName;

		unsigned percentage = 0;
		for(unsigned short j=index;fileLineCoverage[j];j++){

			FileLineCoverage* flc = fileLineCoverage[j];
			FunctionCoverage* fc = flc->owner;

			if(strcmp(fileName,flc->fileName))
				break;

			file << "\t\t\t[list \\" << endl
			     << "\t\t\t\t" << (int)(flc->executionPercentage) << " \\" << endl;

			pthread_mutex_lock(&(fc->updateLock));

			unsigned es = flc->executedLines.size();

			file << "\t\t\t\t" << es << " \\" << endl
			     << "\t\t\t\t" << flc->lineCount << " \\" << endl;

			if(es){
				percentage += es;
				file << "\t\t\t\t[list \\" << endl;
				unsigned short* elements =
					 new unsigned short[es];
				flc->executedLines.elements(elements);
				for(unsigned t=0;t<es;t++)
					file << elements[t] << " ";
				delete[] elements;
				file << "\\" << endl;
				file << "\t\t\t\t] \\" << endl;
			}
			pthread_mutex_unlock(&(fc->updateLock));

			file << "\t\t\t] \\" << endl;
		}
		file << "\t\t] \\" << endl
		     << "\t\t" << (int)(((1.0*percentage)/fileLineCount[i])*100) << " \\" << endl
		     << "\t\t" << percentage << " \\" << endl
		     << "\t\t" << fileLineCount[i] << " \\" << endl
		     << "\t]" << endl;
	}
	for(unsigned int i=0;i<frequencyCode.size();i++){
		file << "set globalFrequencyMap(" << i+1 << ") [list "
		     << frequencyLine[i] << " " << frequencyCode[i] << " ]" << endl;
	}

	pthread_mutex_unlock(&updateLock);
	
   }
   else {
	if(globalInterp && statusBarName){
		pthread_mutex_lock(&statusUpdateLock);
		tclStatusChanged = true;
		sprintf(tclStatusBuffer,"%s configure -text \
			\"Can not update executed line information (no deletion)...\"",
			statusBarName);
		pthread_mutex_unlock(&statusUpdateLock);
	}
   }
}

void CodeCoverage::getTclTkMenuListCreation(ofstream& file){

	for(int i=0;i<fileCount;i++){
		file << "set globalDataStructure(" << i << ") \\" << endl;

		unsigned short index = fileStartIndex[i];
		const char* fileName = fileLineCoverage[index]->fileName;

		file << "\t[list \\" << endl;
		file << "\t\t" << fileName << " \\" << endl;

		file << "\t\t[list \\" << endl;
		for(unsigned short j=index;fileLineCoverage[j];j++){
			FileLineCoverage* flc = fileLineCoverage[j];
			FunctionCoverage* fc = flc->owner;
			if(strcmp(fileName,flc->fileName))
				break;
			file << "\t\t\t" << fc->functionName << " \\" << endl;
		}
		file << "\t\t] \\" << endl;
		file << "\t\t[list \\" << endl;
		for(unsigned short j=index;fileLineCoverage[j];j++){
			FileLineCoverage* flc = fileLineCoverage[j];
			if(strcmp(fileName,flc->fileName))
				break;

			unsigned short minLine = 
				(flc->unExecutedLines.size() ?
					flc->unExecutedLines.minimum():
					0);

			file << "\t\t\t" << minLine << " \\" << endl;
		}
		file << "\t\t]]" << endl;
	}
	for(int i=0;i<fileCount;i++){
		file << "set globalExecutionMap(" << i << ") \\" << endl;
		file << "\t[list \\" << endl;
		file << "\t\t[list \\" << endl;

		unsigned short index = fileStartIndex[i];
		const char* fileName = fileLineCoverage[index]->fileName;

		for(unsigned short j=index;fileLineCoverage[j];j++){
			FileLineCoverage* flc = fileLineCoverage[j];
			if(strcmp(fileName,flc->fileName))
				break;
			file << "\t\t\t[list \\" << endl
			     << "\t\t\t\t0 \\" << endl
			     << "\t\t\t\t0 \\" << endl
			     << "\t\t\t\t" << flc->lineCount << " \\" << endl
			     << "\t\t\t] \\" << endl;
		}
		file << "\t\t] \\" << endl
		     << "\t\t0 \\" << endl
		     << "\t\t0 \\" << endl
		     << "\t\t" << fileLineCount[i] << " \\" << endl
		     << "\t]" << endl;
	}
	file << "InitializeInterface \\" << endl
	     << "\t.menuFrame.listFrame.fileListFrame \\" << endl
	     << "\t.fileFrame.displayPanel.text \\" << endl
	     << "\t0 \\" << endl
	     << "\tglobalDataStructure \\" << endl
	     << "\tglobalExecutionMap \\" << endl;

}

/** method to set tcl/tk related things to CodeCoverage */
void CodeCoverage::setTclTkSupport(Tcl_Interp* interp,const char* statusBar){
	globalInterp = interp;
	statusBarName = statusBar;
}

/** method to print the coverage results after reading
  * from the binary file produced by code coverage tool.
  */
int CodeCoverage::viewCodeCoverageInfo(char* fN){
	unsigned tmp_u;
	unsigned short tmp_s;
	char buffer[1024];

	ifstream inputFile;
	inputFile.open(fN,ios::in);

	if(!inputFile)
		return errorPrint(Error_FileOpen,fN);

	char ccid[10];
	inputFile.read(ccid,10);
	if(strncmp(ccid,"Dyncov-1.0",10))
		return errorPrint(Error_FileFormat,fN);

	while(true){

		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		if(!tmp_u)
			break;

		cout << "# # # # # # # # # # # # # # # # # # # "
		     << "# # # # # # # # # # # # # # # # # # #" << endl; 
		inputFile.read(buffer,tmp_u);buffer[tmp_u] = '\0';
		cout << "** Function  :  " << buffer << endl;

		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		inputFile.read(buffer,tmp_u);buffer[tmp_u] = '\0';
		cout << "** File      :  " << buffer << endl;

		cout << "** Executed  : ";
		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		unsigned nofe = tmp_u;
		for(unsigned i=1;i<=tmp_u;i++){
			inputFile.read((char*)&tmp_s,sizeof(unsigned short));
			cout << " " << tmp_s;
			if(!(i % 10) && (i < tmp_u))
				cout << endl << "              ";
		}

		cout << endl << "** UnExecuted: ";
		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		unsigned nofu = tmp_u;
		for(unsigned i=1;i<=tmp_u;i++){
			inputFile.read((char*)&tmp_s,sizeof(unsigned short));
			cout << " " << tmp_s;
			if(!(i % 10) && (i < tmp_u))
				cout << endl << "              ";
		}

		cout << endl << "[ Percentage : ";
		if(nofe+nofu) 
			cout << ((float)nofe/(nofe+nofu))*100;
		else
			cout << "0.0";
		cout << " % ]" << endl << endl;
	}

	inputFile.close();

	return Error_OK;
}

typedef struct {
	char* fileName;
	char* funcName;
	unsigned short min;
	unsigned total;
	BPatch_Set<unsigned short> executed;
} COVINFO;

int FCSortCOVINFO(const void* arg1,const void* arg2){
	COVINFO* e1 = *((COVINFO* const *)arg1);
	COVINFO* e2 = *((COVINFO* const *)arg2);

	int check = strcmp(e1->fileName,e2->fileName);
	if(check > 0)
		return 1;
	if(check < 0)
		return -1;

	check = strcmp(e1->funcName,e2->funcName);

	if(check > 0)
		return 1;
	if(check < 0)
		return -1;

	return 0;
}

int CodeCoverage::getTclTkMenuListForView(char* fN,ofstream& file){
	
	unsigned tmp_u;
	unsigned short tmp_s;

	unsigned allInfoSize = 0;
	COVINFO** allInfo = NULL;

	ifstream inputFile;
	inputFile.open(fN,ios::in);

	if(!inputFile)
		return errorPrint(Error_FileOpen,fN);

	char ccid[10];
	inputFile.read(ccid,10);
	if(strncmp(ccid,"Dyncov-1.0",10))
		return errorPrint(Error_FileFormat,fN);

	while(true){

		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		if(!tmp_u)
			break;

		COVINFO* covInfo = new COVINFO;
		covInfo->funcName = new char[tmp_u+1];
		inputFile.read(covInfo->funcName,tmp_u);covInfo->funcName[tmp_u] = '\0';

		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		covInfo->fileName = new char[tmp_u+1];
		inputFile.read(covInfo->fileName,tmp_u);covInfo->fileName[tmp_u] = '\0';

		covInfo->min = 0xffff;
		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		unsigned nofe = tmp_u;
		for(unsigned i=1;i<=tmp_u;i++){
			inputFile.read((char*)&tmp_s,sizeof(unsigned short));
			covInfo->executed += tmp_s;
			if(tmp_s < covInfo->min)
				covInfo->min = tmp_s;
				
		}

		inputFile.read((char*)&tmp_u,sizeof(unsigned));
		unsigned nofu = tmp_u;
		for(unsigned i=1;i<=tmp_u;i++){
			inputFile.read((char*)&tmp_s,sizeof(unsigned short));
			if(tmp_s < covInfo->min)
				covInfo->min = tmp_s;
		}

		covInfo->total = nofe+nofu;

		allInfo = (COVINFO**)realloc((void*)allInfo,(allInfoSize+1)*sizeof(COVINFO*));
		allInfo[allInfoSize++] = covInfo;
	}

	if(!allInfo){
		inputFile.close();
		return Error_OK;
	}

	qsort((void*)allInfo,allInfoSize,sizeof(COVINFO*),
		      FCSortCOVINFO);

	unsigned fileInfoSize = 0;
	unsigned short* fileInfo = new unsigned short[allInfoSize];
	
	char* fileName = "no file name";
	for(unsigned short i=0;i<allInfoSize;i++){
		if(strcmp(fileName,allInfo[i]->fileName)){
			fileName = allInfo[i]->fileName;
			fileInfo[fileInfoSize] = i;
			fileInfoSize++;
		}
	}

	fileName = "no file name";
	for(unsigned i=0;i<fileInfoSize;i++){
		file << "set globalDataStructure(" << i << ") \\" << endl;
		unsigned index = fileInfo[i];
		fileName = allInfo[index]->fileName;
		/*char* p = fileName;p++;*/
		/*p = strchr(p,'/');*/
		
		file << "\t[list \\" << endl
		     /*<< "\t\t/baffie" << p << " \\" << endl*/
		     << "\t\t" << fileName  << " \\" << endl
		     << "\t\t[list \\" << endl;

		for(unsigned j=index;j<allInfoSize;j++){
			COVINFO* fc = allInfo[j];
			if(strcmp(fileName,fc->fileName))
				break;
			file << "\t\t\t" << fc->funcName << " \\" << endl;
		}
		file << "\t\t] \\" << endl
		     << "\t\t[list \\" << endl;
		for(unsigned j=index;j<allInfoSize;j++){
			COVINFO* fc = allInfo[j];
			if(strcmp(fileName,fc->fileName))
				break;
			file << "\t\t\t" << fc->min << " \\" << endl;
		}
		file << "\t\t]]" << endl;
	}
	for(unsigned i=0;i<fileInfoSize;i++){
		file << "set globalExecutionMap(" << i << ") \\" << endl
		     << "\t[list \\" << endl
		     << "\t\t[list \\" << endl;
		unsigned index = fileInfo[i];
		fileName = allInfo[index]->fileName;
		unsigned percentage = 0;
		unsigned total = 0;
		for(unsigned j=index;j<allInfoSize;j++){
			COVINFO* fc = allInfo[j];
			if(strcmp(fileName,fc->fileName))
				 break;

			unsigned es = fc->executed.size();
			file << "\t\t\t[list \\" << endl
			     << "\t\t\t\t" << (int)(((1.0*es)/fc->total)*100) << " \\" << endl
			     << "\t\t\t\t" << es << " \\" << endl
			     << "\t\t\t\t" << fc->total << " \\" << endl;

			percentage += es;
			total += fc->total;

			if(es){
				file << "\t\t\t\t[list \\" << endl;
				unsigned short* elements =
					new unsigned short[es];
				fc->executed.elements(elements);
				for(unsigned t=0;t<es;t++)
					file << elements[t] << " ";
				delete[] elements;
				file << "\\" << endl
				     << "\t\t\t\t] \\" << endl;
			}
			file << "\t\t\t] \\" << endl;
		}
		file << "\t\t] \\" << endl
		     << "\t\t" << (int)(((1.0*percentage)/total)*100) << " \\" << endl
		     << "\t\t" << percentage << " \\" << endl
		     << "\t\t" << total << " \\" << endl
		     << "\t]" << endl;
	}

	file << "InitializeInterface \\" << endl
	     << "\t.menuFrame.listFrame.fileListFrame \\" << endl
	     << "\t.fileFrame.displayPanel.text \\" << endl
	     << "\t0 \\" << endl
	     << "\tglobalDataStructure \\" << endl
	     << "\tglobalExecutionMap \\" << endl;

	for(unsigned i=0;i<allInfoSize;i++)
		delete allInfo[i];
	free(allInfo);

	inputFile.close();

	return Error_OK;
}

bool CodeCoverage::getTclStatusUpdateString(char* buffer,int length){
	bool ret = false;
	pthread_mutex_lock(&statusUpdateLock);
	ret = tclStatusChanged;
	strncpy(buffer,tclStatusBuffer,length);
	tclStatusChanged = false;
	pthread_mutex_unlock(&statusUpdateLock);
	return ret;
}
