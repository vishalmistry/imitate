#include <iostream>
#include <list>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>

#include "BPatch.h"
#include "BPatch_Vector.h"
#include "BPatch_process.h"
#include "BPatch_snippet.h"
#include "BPatch_function.h"

#include "dyninstCompat.h"
#include "config.h"
#include "ipc.h"
#include "log.h"

using namespace std;

void printSummary(BPatch_thread *, BPatch_exitType);
void reportNewProcess(BPatch_thread *, BPatch_thread *);

dynHandle *mutatorInit(void)
{
    dynHandle *dh = new dynHandle;
    if (!dh) {
	dlog(ERR, "Could not allocate %d bytes of memory in mutatorInit().\n", sizeof(dynHandle));
	return NULL;
    }

    sendMsg(config.outfd, ID_INIT_CREATE_BPATCH, INFO);
    dh->bpatch = new BPatch;
    if (!dh->bpatch) {
	sendMsg(config.outfd, ID_INIT_CREATE_BPATCH, INFO, ID_FAIL,
		"Failure creating new BPatch object");
	return NULL;
    } else
	sendMsg(config.outfd, ID_INIT_CREATE_BPATCH, INFO, ID_PASS);

    /*
     * BPatch class level flags.
     */
    dh->bpatch->setDelayedParsing(true);
    if (config.use_merge_tramp) {
	sendMsg(config.outfd, ID_INIT_MERGE_TRAMP, INFO);
	dh->bpatch->setMergeTramp(true);
	sendMsg(config.outfd, ID_INIT_MERGE_TRAMP, INFO, ID_PASS);
    }

    /*
     * We should probably have a notion of a default callback
     * handler to return here instead of NULL to differentiate
     * between the error case.
     */
    sendMsg(config.outfd, ID_INIT_REGISTER_EXIT, INFO);
    dh->bpatch->registerExitCallback(printSummary);
    sendMsg(config.outfd, ID_INIT_REGISTER_EXIT, INFO, ID_PASS);

    sendMsg(config.outfd, ID_INIT_REGISTER_FORK, INFO);
    dh->bpatch->registerPostForkCallback(reportNewProcess);
    sendMsg(config.outfd, ID_INIT_REGISTER_FORK, INFO, ID_PASS);

    if (config.use_attach) {
	sendMsg(config.outfd, ID_INIT_ATTACH_PROCESS, INFO);
	dh->proc = dh->bpatch->processAttach(config.target, config.attach_pid);
	if (!dh->proc) {
	    sendMsg(config.outfd, ID_INIT_ATTACH_PROCESS, INFO, ID_FAIL,
		    "Failure in BPatch::processAttach()");
	    return NULL;
	} else {
	    config.dynlib = dh;
	    sendMsg(config.outfd, ID_INIT_ATTACH_PROCESS, INFO, ID_PASS,
		    dh->proc->getPid());
	}

    } else {
	sendMsg(config.outfd, ID_INIT_CREATE_PROCESS, INFO);
	dh->proc = dh->bpatch->processCreate(config.target, (const char **)config.argv);
	if (!dh->proc) {
	    sendMsg(config.outfd, ID_INIT_CREATE_PROCESS, INFO, ID_FAIL,
		    "Failure in BPatch::processCreate()");
	    return NULL;
	} else {
	    config.dynlib = dh;
	    sendMsg(config.outfd, ID_INIT_CREATE_PROCESS, INFO, ID_PASS,
		    dh->proc->getPid());
	}
    }

    if (config.use_save_world) {
	sendMsg(config.outfd, ID_INIT_SAVE_WORLD, INFO);
	dh->proc->enableDumpPatchedImage();
	sendMsg(config.outfd, ID_INIT_SAVE_WORLD, INFO, ID_PASS);
    }

    sendMsg(config.outfd, ID_INIT_GET_IMAGE, INFO);
    dh->image = dh->proc->getImage();
    if (!dh->image) {
	sendMsg(config.outfd, ID_INIT_GET_IMAGE, INFO, ID_FAIL,
		"Failure in BPatch_process::getImage()");
	return NULL;
    } else
	sendMsg(config.outfd, ID_INIT_GET_IMAGE, INFO, ID_PASS);

    return dh;
}

bool dynStartTransaction(dynHandle *dh)
{
    sendMsg(config.outfd, ID_INST_START_TRANS, INFO);
    dh->proc->beginInsertionSet();
    sendMsg(config.outfd, ID_INST_START_TRANS, INFO, ID_PASS);
    return true;
}

bool dynEndTransaction(dynHandle *dh)
{
    sendMsg(config.outfd, ID_INST_END_TRANS, INFO);
    if (!dh->proc->finalizeInsertionSet(false)) {
	sendMsg(config.outfd, ID_INST_END_TRANS, INFO, ID_FAIL,
		"Instrumentation transaction failed.  Program left in unknown state.");
	return false;
    }
    sendMsg(config.outfd, ID_INST_END_TRANS, INFO, ID_PASS);
    return true;
}
