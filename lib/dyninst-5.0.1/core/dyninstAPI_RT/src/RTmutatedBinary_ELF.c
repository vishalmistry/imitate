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

/* $Id: RTmutatedBinary_ELF.c,v 1.26 2006/06/13 04:21:12 legendre Exp $ */

/* this file contains the code to restore the necessary
   data for a mutated binary 
 */

#include <stdlib.h>
#include "dyninstAPI_RT/h/dyninstAPI_RT.h"
#include <unistd.h>
#include  <fcntl.h>
#include <string.h>

#include <libelf.h>



#if defined(sparc_sun_solaris2_4)
#include <procfs.h> /* ccw 12 mar 2004*/
#include <sys/types.h>
#include <sys/stat.h>
#endif



#if defined(i386_unknown_linux2_0) \
 || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */
#define __USE_GNU
#endif

#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h> /* ccw 23 jan 2002 */
#if defined(sparc_sun_solaris2_4) 

#include <sys/link.h>
#include <signal.h>
#endif
#include <limits.h>

#if defined(sparc_sun_solaris2_4)
extern void* _DYNAMIC;

#if defined(__arch64__)
#define __ELF_NATIVE_CLASS 64
#else
#define __ELF_NATIVE_CLASS 32
#endif

/* Borrowed from Linux's link.h:  Allows us to use data types
   from libelf regardless of word size. */
#define ElfW(type)      _ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)  e##w##t


#elif defined(i386_unknown_linux2_0) \
   || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */
extern ElfW(Dyn) _DYNAMIC[];

#endif

/* Borrowed from Linux's link.h: Allows us to use functions from
   libelf regardless of word size. */
//#define ELF_FUNC(type)      _ELF_FUNC (elf, __ELF_NATIVE_CLASS, type)
#define ELF_FUNC(type)      _ELF_FUNC (Elf, __ELF_NATIVE_CLASS, type)
#define _ELF_FUNC(e,w,t)    _ELF_FUNC_1 (e, w, _##t)
#define _ELF_FUNC_1(e,w,t)  e##w##t

typedef struct {
      ElfW(Sword) d_tag;
      union {
          ElfW(Sword) d_val;
          ElfW(Addr) d_ptr;
      } d_un;
  } __Elf_Dyn;

unsigned long checkAddr;
/*extern int isMutatedExec;
char *buffer;
*/

struct link_map* map=NULL;

#if defined(sparc_sun_solaris2_4)

prmap_t *procMemMap=NULL;/* ccw 2 apr 2002 */
int procMemMapSize=0;

struct r_debug _r_debug; /* ccw 2 apr 2002 */
int r_debug_is_set = 0; 
extern unsigned int _dyninst_call_to_dlopen;
extern unsigned int __dyninst_jump_template__;
extern unsigned int __dyninst_jump_template__done__;
#endif

char *sharedLibraryInfo = NULL;
unsigned int originalInsnBkpt;
unsigned int addressBkpt;

#if defined(sparc_sun_solaris2_4)
/* 	To help the RT shared lib to reload in the same location for the
   	mutated binaries we now use dldump to dump the rt lib back to the
	directory that contains the mutated binary.  The LD_LIBRARY_PATH
	MUST be set to find this new rt lib ONLY when running the mutated
	binary.
*/
extern char gLoadLibraryErrorString[ERROR_STRING_LENGTH];

int DYNINSTsaveRtSharedLibrary(char *rtSharedLibName, char *newName){

	char *err_str;
	gLoadLibraryErrorString[0]='\0';

	/*fprintf(stderr," DLDUMP(%s,%s)\n",  rtSharedLibName, newName);*/

	/* dldump returns 0 on success */
	if ( dldump(rtSharedLibName, newName, RTLD_REL_RELATIVE) ) { 
		/* An error has occurred */
		perror( "DYNINSTsaveRtSharedLibrary -- dldump" );
    
		if (NULL != (err_str = dlerror())){
			strncpy(gLoadLibraryErrorString, err_str, ERROR_STRING_LENGTH);
		}else{ 
			sprintf(gLoadLibraryErrorString,"unknown error with dldump");
		}
    
		/*fprintf(stderr, "%s[%d]: %s\n",__FILE__,__LINE__,gLoadLibraryErrorString);*/
		return 0;  
	} else{
    		return 1;
	}
}
#endif
/* 	this is not misnamed.  In the future, this function will contain
	code to patch the instrumentation of a shared library that has 
	been loaded into a different place during a mutated binary run.

	Now, it just exit()s, as you can see
*/

void fixInstrumentation(char* soName, unsigned long currAddr, unsigned long oldAddr){
	printf(" %s loaded at wrong address: 0x%lx (expected at 0x%lx) \n", soName, currAddr, oldAddr);
	printf(" This is an unrecoverable error, the instrumentation will not");
	printf("\n run correctly if shared libraries are loaded at a different address\n");
	printf("\n Exiting.....\n");
	fflush(stdout);
	exit(9);
}

/* 	this function checks the shared library (soName) to see if it
	is currently loaded (loadAddr) at the same place it was before (address).
	If the shared library is not found in the list (sharedLibraryInfo) that
	mean the shared library was *NOT* instrumented and can be loaded
	anywhere
*/
unsigned long checkSOLoadAddr(char *soName, unsigned long loadAddr){
	unsigned long result=0, found = 0;
	unsigned long address;
	char *ptr = sharedLibraryInfo;
	while(ptr &&  *ptr && !found ){
		/*fprintf(stderr," CHECKING FOR %s in %s\n", ptr, soName);*/

        	if(strstr(soName, ptr) || strstr(ptr,soName)){
                	found = 1;
			ptr += (strlen(ptr) +1);
			memcpy(&address, ptr, sizeof(unsigned long)); 
			/* previous line is done b/c of alignment issues on sparc*/
			if(loadAddr == address) {
				result = 0;
			}else{
				result = address;
			}	
		}

		ptr += (strlen(ptr) +1);
		ptr += sizeof(unsigned long);
		ptr += sizeof(unsigned long); /* for flag */


	}
	if(!found){
		result = 0;
		/*fprintf(stderr," NOT FOUND %s\n",soName);*/
	}

	/*fprintf(stderr," checkSOLoadAddr: %s %lx %lx\n", soName, loadAddr, result);*/
	return result;
}
#if defined(sparc_sun_solaris2_4)
unsigned int register_o7;

unsigned long loadAddr;
/*	this function is not a signal handler. it was originally but now is 
	not, it is called below in dyninst_jump_template
*/ 
void pseudoSigHandler(int sig){

	map = _r_debug.r_map; /* ccw 22 jul 2003*/
	if(_r_debug.r_state == 0){
		do{
			if(map->l_next){
				map = map->l_next;
			}
			loadAddr = checkSOLoadAddr(map->l_name, map->l_addr);
			if(loadAddr){
				fixInstrumentation(map->l_name, map->l_addr, loadAddr);
			}

		}while(map->l_next);

	}

}

void dyninst_jump_template(){
/* THE PLAN:

	The Solaris loader/ELF file works as follows:
	
	A call to dlopen jumps to the Procedure Linking Table 
	slot holding the dlopen information.  This slot consists of
	three instructions:
	
	sethi r1, 0xb4
	ba (to another PLT slot)
	nop

	The second PLT slot contains three instructions:
	save
	call (address of dlopen)
	nop

	dlopen returns directly to where it was called from, not to
	either of the PLT slots.  The address from which it was called
	is located in %o7 when the call to dlopen in the second PLT
	slot is made. dlopen returns to %o7 +4.
	

	What our code does:

	The goals is to intercept this call to dlopen by overwritting
	the first PLT slot to jump to __dyninst_jump_template__ then we
	can jump to code that will check the addresses of the loaded
	shared libraries.

	first we must preserver %o7 so we know where to go back to.
	This is done with the first two instructions in __dyninst_jump_template__
	These are written as nops BUT are overwritten in the SharedLibraries 
	branch in checkElfFile.  %o7 is saved in register_o7 declared above.
	This address is not available until run time so we generate these
	instructions on the fly.

	Next, we CALL the second PLT slot as normal.  We use the delay
	slot to run the sethi instruction from the first PLT slot. These
	instructions are generated at runtime. 

	dlopen will eventually be called and will return to the nop after
	the sethi.  Now we need to call our function to check the
	shared library address.  This is pseudoSigHandler.  We must
	preserve the data returned by dlopen so we do a save to
	push the register onto the stack before we call our function.
	We call our function, and then do a restore to retreive the 
	saved information.

	At __dyninst_jump_template__done__ we want to restore the
	value in register_o7 to %o7 so when we do a retl we will
	jump back to where the mutated binary originally called 
	dlopen.
	The sethi and ld instructions are generated on the fly just
	as the first sethi and st pair that saved the value of %o7.
	The retl used %o7 to jump back to the original place 
	the mutatee called dlopen. We are done. Whew.

	Note that I know the address of the first PLT slot because
	the mutator found it and saved it in the mutated binary.
	The address of the second PLT slot is determined by looking
	at the instructions in the first PLT slot.
*/
	

	asm("nop");
	asm("__dyninst_jump_template__:");

	asm("nop"); 	/*sethi hi(register_o7), %g1 GENERATED BELOW*/
	asm("nop");	/*st %o7 GENERATED BELOW*/

	asm("nop");	/*call/jmp plt GENERATED BELOW*/
	asm("nop");    /*sethi r1, b4 GENERATED BELOW*/

	asm("nop");
	asm("save %sp, -104, %sp");
	asm("nop");
	pseudoSigHandler(0);
	asm("nop");
	asm("restore");
	asm("nop");
	asm("nop");
	asm("__dyninst_jump_template__done__:");
	asm("nop"); 	/*sethi hi(register_o7), %g1 GENERATED BELOW*/
	asm("nop"); 	/* ld [register_o7], %o7 GENERATED BELOW*/
	asm("retl");

	asm("nop"); 	/* this will be filled in below */
	asm("nop");

}

#endif

#if defined (sparc_sun_solaris2_4)
void findMap(){ /* ccw 12 mar 2004*/

	Dl_info dlip;
	int me = getpid();
	char fileName[1024];
	prmap_t mapEntry;
	int fd;
	int index = 0;
	int offset = 0;
	struct stat statInfo;

	sprintf(fileName, "/proc/%d/map", me);
	
	stat(fileName, &statInfo);
	if( procMemMap ) {
		free(procMemMap);
	}
	procMemMap = (prmap_t*) malloc(statInfo.st_size);

	fd = open(fileName, O_RDONLY);

	while( pread(fd, (void*)& (procMemMap[index]), sizeof(mapEntry), offset) ){
		offset += sizeof(prmap_t);
		index++;
	}
	close(fd);
	procMemMapSize = index;

}

long checkMap(unsigned long addr){
	int index=0;

	findMap();	
	while(index < procMemMapSize){
		if( procMemMap[index].pr_vaddr <= addr && (procMemMap[index].pr_vaddr + (unsigned int)procMemMap[index].pr_size) > addr){
			return 1;
		}
		index++;
	}
	return 0;
}
#endif

#if defined(i386_unknown_linux2_0) \
 || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */
unsigned long loadAddr;
void (*dl_debug_state_func)(void);

void dyninst_dl_debug_state(){
	asm("nop");
	if(_r_debug.r_state == 1){
	do {
			if(map->l_next){
				map = map->l_next;
			}
			loadAddr = checkSOLoadAddr(map->l_name, (unsigned long)map->l_ld);/*l_addr*/
			if(loadAddr){
				fixInstrumentation(map->l_name, (unsigned long)map->l_ld, loadAddr);/*l_addr*/
			}
		}while(map->l_next);

	}

	/* the following call is used to call
	 * _dl_debug_state to ensure correctness (if
	 * someone relies on it being called it is
	 * execuated after this function)
	 * The value stored in dl_debug_state_func is
	 * the address of the function _dl_debug_state
	 * and is set in checkElfFile
	 */
	asm("nop");
	asm("nop");
	asm("nop");
	(*dl_debug_state_func)();
	asm("nop");

}

void hack_ld_linux_plt(unsigned long pltEntryAddr){ 
/* this is ugly.
 * save the world needs to check each shared library
 * that is loaded to ensure that it is loaded at the
 * same base address it was loaded at when the mutator/mutatee
 * pair ran.  
 * So, we know dlopen calls _dl_debug_state per the r_debug
 * interface to let the process know a shared library has changed
 * state.
 * with this function we change the Procedure Linkage Table (.plt)
 * for ld-linux.so so that the entry that used to point to
 * _dl_debug_state points to dyninst_dl_debug_state.
 *
 * dyninst_dl_debug_state then calls _dl_debug_state before
 * exiting 
 *
 * dont try this at home
 */
	unsigned long mprotectAddr = pltEntryAddr - (pltEntryAddr % getpagesize());	
	unsigned long newTarget = (unsigned long) &dyninst_dl_debug_state ;
	
	mprotect( (void*) mprotectAddr, pltEntryAddr - mprotectAddr + sizeof(long), 
				PROT_READ|PROT_WRITE|PROT_EXEC);

	memcpy( (void*) dl_debug_state_func, (void*) pltEntryAddr, sizeof(long)); 

	memcpy( (void*) pltEntryAddr, &newTarget, sizeof(long));
}
#endif

unsigned (*Elf_version)(unsigned) = NULL;
Elf *(*Elf_begin)(int fildes, Elf_Cmd cmd, Elf *ref) = NULL;
Elf_Scn *(*Elf_getscn)(Elf *elf, size_t index) = NULL;
Elf_Data *(*Elf_getdata)(Elf_Scn *scn, Elf_Data *data) = NULL;
Elf_Scn *(*Elf_nextscn)(Elf *elf, Elf_Scn *scn) = NULL;
Elf32_Shdr *(*Elf32_getshdr)(Elf_Scn *scn) = NULL;
Elf32_Ehdr *(*Elf32_getehdr)(Elf *elf) = NULL;
Elf64_Shdr *(*Elf64_getshdr)(Elf_Scn *scn) = NULL;
Elf64_Ehdr *(*Elf64_getehdr)(Elf *elf) = NULL;
const char *(*Elf_errmsg)(int err) = NULL;
int (*Elf_errno)(void) = NULL;
int (*Elf_end)(Elf *elf) = NULL;


int checkSO(char* soName){
	ElfW(Shdr) *shdr;
	ElfW(Ehdr) *   ehdr;
    	Elf *          elf;
	int       fd;
	Elf_Data *strData;
	Elf_Scn *scn;
	int result = 0;

 	if((fd = (int) open(soName, O_RDONLY)) == -1){
		RTprintf("cannot open : %s\n",soName);
    		fflush(stdout); 
		return result;
	}
	if((elf = Elf_begin(fd, ELF_C_READ, NULL)) ==NULL){
		RTprintf("%s %s \n",soName, Elf_errmsg(Elf_errno()));
		RTprintf("cannot elf_begin\n");
		fflush(stdout);
		close(fd);
		return result;
	}

	ehdr = ELF_FUNC( getehdr(elf) );
	scn = Elf_getscn(elf, ehdr->e_shstrndx);
	strData = Elf_getdata(scn,NULL);
   	for( scn = NULL; !result && (scn = Elf_nextscn(elf, scn)); ){
		shdr = ELF_FUNC( getshdr(scn) );
		if(!strcmp((char *)strData->d_buf + shdr->sh_name, ".dyninst_mutated")) {
			result = 1;
		}
	}
	Elf_end(elf);
	close(fd);

	return result;
}

int checkMutatedFile(){


	ElfW(Shdr) *shdr;
	ElfW(Ehdr) *   ehdr;
	Elf *          elf;
	int       cnt,fd;
	Elf_Data *elfData,*strData;
	Elf_Scn *scn;
	char *execStr;
	int retVal = 0;
	unsigned long mmapAddr;
	int pageSize;
	Address dataAddress;
	int dataSize;
	char* tmpPtr;
	unsigned long updateAddress, updateSize, updateOffset;
	unsigned long *dataPtr;
	unsigned int numberUpdates,i ;
	char* oldPageData;
	Dl_info dlip;
	int soError = 0; 

     char * error_msg = NULL;
     void * elfHandle = NULL;

	//fprintf(stderr,"SBRK 0x%x\n",sbrk(1));;

//     elfHandle = dlopen("/usr/lib/libelf.so.1", RTLD_NOW);

     elfHandle = dlopen("libelf.so", RTLD_NOW);
     if(! elfHandle){
        error_msg = dlerror();
        if (error_msg) {
          //fprintf(stderr,"Could not open lib: %s- %s\n","libelf",error_msg);
        }
        else{
          //fprintf(stderr, "failure\n");
        }
	return 0;
     }

     Elf_version = (unsigned (*)(unsigned)) dlsym(elfHandle, "elf_version");
     Elf_begin = (Elf *(*)(int,Elf_Cmd,Elf *)) dlsym(elfHandle, "elf_begin");
     Elf_getscn = (Elf_Scn *(*)(Elf *, size_t)) dlsym(elfHandle, "elf_getscn");
     Elf_nextscn = (Elf_Scn *(*)(Elf *, Elf_Scn *)) dlsym(elfHandle, "elf_nextscn");
     Elf_getdata = (Elf_Data *(*)(Elf_Scn *, Elf_Data *)) dlsym(elfHandle, "elf_getdata");
     Elf32_getehdr = (Elf32_Ehdr *(*)(Elf *)) dlsym(elfHandle, "elf32_getehdr");
     Elf32_getshdr = (Elf32_Shdr *(*)(Elf_Scn *)) dlsym(elfHandle, "elf32_getshdr");
     Elf64_getehdr = (Elf64_Ehdr *(*)(Elf *)) dlsym(elfHandle, "elf64_getehdr");
     Elf64_getshdr = (Elf64_Shdr *(*)(Elf_Scn *)) dlsym(elfHandle, "elf64_getshdr");
     Elf_errmsg = (const char *(*)(int)) dlsym(elfHandle, "elf_errmsg");
     Elf_errno = (int (*)(void)) dlsym(elfHandle, "elf_errno");
     Elf_end = (int (*)(Elf *)) dlsym(elfHandle, "elf_end");

	Elf_version(EV_CURRENT);

	execStr = (char*) malloc(1024);
	memset(execStr,'\0',1024);

#if defined(sparc_sun_solaris2_4)
        sprintf(execStr,"/proc/%d/object/a.out",getpid());
#elif defined(i386_unknown_linux2_0) \
   || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */
	sprintf(execStr,"/proc/%d/exe",getpid());
#endif

	if((fd = (int) open(execStr, O_RDONLY)) == -1){
		printf("cannot open : %s\n",execStr);
    		fflush(stdout); 
		return retVal;
	}
	if((elf = Elf_begin(fd, ELF_C_READ, NULL)) ==NULL){
		printf("%s %s \n",execStr, Elf_errmsg( Elf_errno()));
		printf("cannot Elf_begin\n");
		fflush(stdout);
		close(fd);
		return retVal;
	}

	ehdr = ELF_FUNC( getehdr(elf) );
	scn = Elf_getscn(elf, ehdr->e_shstrndx);
	strData = Elf_getdata(scn,NULL);
	pageSize =  getpagesize();

	/*fprintf(stderr,"IN MUTATED FILE\n");*/
   	for(cnt = 0, scn = NULL; !soError &&  (scn = Elf_nextscn(elf, scn));cnt++){
		shdr = ELF_FUNC( getshdr(scn) );
		if(!strncmp((char *)strData->d_buf + shdr->sh_name, "dyninstAPItrampgu", 17)) {
			dataAddress = shdr->sh_addr;
			elfData = Elf_getdata(scn, NULL);
			tmpPtr = elfData->d_buf;
			//fprintf(stderr,"tramp guard addr %x \n", dataAddress);


			/* 	we already own it. 
	
				because we have moved the start of the heap beyond this address
			*/

			/* set tramp guard to 1 */
			for(i=0;i<*(int*)tmpPtr;i++){
				((unsigned*) dataAddress)[i]=1;
			}

		}else if(!strncmp((char *)strData->d_buf + shdr->sh_name, "dyninstAPI_data", 15)) {
			elfData = Elf_getdata(scn, NULL);
			tmpPtr = elfData->d_buf;
			dataAddress = -1;
			while( dataAddress != 0 ) { 
				/*tmpPtr may not be aligned on the correct boundry
				so use memcpy to set dataSize
				dataSize = *(int*) tmpPtr;*/
				memcpy((char*) & dataSize, tmpPtr, sizeof(int));

				tmpPtr+=sizeof(int);
				memcpy( (char*) & dataAddress, tmpPtr, sizeof(Address));

				tmpPtr += sizeof(Address);
				if(dataAddress){
					memcpy((char*) dataAddress, tmpPtr, dataSize);

					tmpPtr += dataSize;
				}
			}

		}else if(!strncmp((char *)strData->d_buf + shdr->sh_name, "dyninstAPI_",11)){ 
			char *tmpStr = strchr((char *)strData->d_buf + shdr->sh_name, (int)'_'); ;

			tmpStr ++;

#if defined(sparc_sun_solaris2_4)
			if( r_debug_is_set == 0 ) { 
				/* this moved up incase there is no dyninstAPI_### section, map and
				_r_debug are still set correctly. */
				/* solaris does not make _r_debug available by
				default, we have to find it in the _DYNAMIC table */

				__Elf_Dyn *_dyn = (__Elf_Dyn*)& _DYNAMIC;	
				while(_dyn && _dyn->d_tag != 0 && _dyn->d_tag != 21){
					_dyn ++;
				}
				if(_dyn && _dyn->d_tag != 0){
					_r_debug = *(struct r_debug*) _dyn->d_un.d_ptr;
				}
				map = _r_debug.r_map;
				r_debug_is_set = 1;
			}else{
				map = _r_debug.r_map;
			}

#endif
			if( *tmpStr>=0x30 && *tmpStr <= 0x39 ) {
				/* we dont want to do this unless this is a dyninstAPI_### section
					specifically, dont do this for dyninstAPI_SharedLibraries*/
				retVal = 1; /* this is a restored run */

				if( *tmpStr>=0x30 && *tmpStr <= 0x39 ) {
					/* this is a heap tramp section */

					/* 	the new starting address of the heap is immediately AFTER the last
						dyninstAPI_### section, so we can ALWAYS memcpy the data into place
						see the value of newHeapAddr in writeBackElf.C
					*/
					elfData = Elf_getdata(scn, NULL);
					memcpy((void*)shdr->sh_addr, elfData->d_buf, shdr->sh_size);
				}
			}
		}
		if(!strcmp((char *)strData->d_buf + shdr->sh_name, "dyninstAPI_mutatedSO")){
			/* make sure the mutated SOs are loaded, not the original ones */
			char *soNames;
			int mutatedFlag = 0;
			int totallen=0;
#if defined(sparc_sun_solaris2_4)
			Link_map *lmap=0;
#elif defined(i386_unknown_linux2_0) \
   || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */
			struct link_map *lmap=0;
#endif
			char *loadedname, *dyninstname;

			elfData = Elf_getdata(scn, NULL);

			sharedLibraryInfo = (char*) malloc(elfData->d_size);
			memcpy(sharedLibraryInfo, elfData->d_buf, elfData->d_size);
			lmap = _r_debug.r_map;

			for(soNames = (char*) elfData->d_buf ; totallen<elfData->d_size; 
				soNames = &((char*) elfData->d_buf)[strlen(soNames)+1+sizeof(unsigned int) +sizeof(unsigned int)]){
				/* added a +sizeof(unsigned int) above for flag */
				totallen += strlen(soNames) + 1 + sizeof(unsigned int) +sizeof(unsigned int); /*for flag*/
				memcpy(&mutatedFlag, &((char*) elfData->d_buf)[totallen-sizeof(unsigned int)], sizeof(unsigned int));
				lmap = _r_debug.r_map;
				while(lmap){
					loadedname = strrchr(lmap->l_name,'/');
					dyninstname =  strrchr((const char *)soNames,(int)'/');
					if(loadedname == 0){
						loadedname = lmap->l_name;
					}
					if(dyninstname == 0){
						dyninstname = soNames;
					}	
					if(mutatedFlag && !strcmp(loadedname, dyninstname)) {
						if(!checkSO(lmap->l_name)){
			printf("ERROR: %s was mutated during saveworld and",lmap->l_name);
			printf(" the currently loaded %s has not been mutated\n", lmap->l_name);
			printf(" check your LD path to be sure the mutated %s is visible\n", soNames);
							soError = 1;
		
						}

		
					}
					lmap = lmap->l_next;
				}
			}
		}
		if(!strcmp((char *)strData->d_buf + shdr->sh_name, "rtlib_addr")){
			unsigned int ptr;
			int done = 0;


			elfData = Elf_getdata(scn, NULL);

			/*ptr = elfData->d_buf;*/
			/* use memcpy because of alignment issues on sparc */	
			memcpy(&ptr,elfData->d_buf,sizeof(unsigned int));

#if defined(sparc_sun_solaris2_4)
               		if( r_debug_is_set == 0 ) {
                    		/* this moved up incase there is no dyninstAPI_### section, map and
                    			_r_debug are still set correctly. */
                    		/* solaris does not make _r_debug available by
                    			default, we have to find it in the _DYNAMIC table */

                    		__Elf_Dyn *_dyn = (__Elf_Dyn*)& _DYNAMIC;
                    		while(_dyn && _dyn->d_tag != 0 && _dyn->d_tag != 21){
                         		_dyn ++;
                    		}
                    		if(_dyn && _dyn->d_tag != 0){
                         		_r_debug = *(struct r_debug*) _dyn->d_un.d_ptr;
                    		}
                    		map = _r_debug.r_map;
                    		r_debug_is_set = 1;
               		}else{
                    		map = _r_debug.r_map;
               		}
#endif
	
			map = _r_debug.r_map;

			while(map && !done){
				/*fprintf(stderr,"CHECKING %s 0x%x\n", map->l_name,map->l_addr);*/
				if( * map->l_name  && strstr(map->l_name, "libdyninstAPI_RT")){
					unsigned long loadaddr = (unsigned long)map->l_addr;

					/* 	LINUX PROBLEM. in the link_map structure the map->l_addr field is NOT
						the load address of the dynamic object, as the documentation says.  It is the
						RELOCATED address of the object. If the object was not relocated then the
						value is ZERO.

						So, on LINUX we check the address of the dynamic section, map->l_ld, which is
						correct.
					*/
#if defined(i386_unknown_linux2_0) || defined(x86_64_unknown_linux2_4)
					loadaddr = (unsigned long)map->l_ld;
#endif

					/*fprintf(stderr," loadadd %x ptr %x\n", loadaddr, ptr);*/
					if( loadaddr !=  (ptr)){
						fixInstrumentation(map->l_name, loadaddr,  (ptr));
					}
				}
				/* check every loaded SO but leave map such that map->l_next == NULL.
					The next time a SO is loaded it will be placed at 
					map->l_next, so keep a tail pointer such that we 
					dont need to loop through the entire list again
				*/
				if(map->l_next){
					map = map->l_next;
				}else{
					done = 1;
				}
			}
		}
		if(!strcmp((char *)strData->d_buf + shdr->sh_name, "dyninstAPI_SharedLibraries")){
			unsigned long diffAddr;
			unsigned long ld_linuxBaseAddr;
#if defined(sparc_sun_solaris2_4)
                        unsigned long baseAddr, size;
			unsigned int *overWriteInsn;
			unsigned int *pltEntry, *PLTEntry, *dyninst_jump_templatePtr, pltInsn, tmpAddr;
			unsigned int BA_MASK=0x30800000;
			unsigned int BA_IMM=0x003fffff;
			unsigned int SETHI_IMM=0x003fffff;
			unsigned int JMP_IMM =0x00001fff;
			unsigned int offset, callInsn;
			struct sigaction  mysigact, oldsigact;
			int result;
#endif
			char *ptr;
			int done = 0;


			elfData = Elf_getdata(scn, NULL);

			ptr = elfData->d_buf;
		
			map = _r_debug.r_map;

			while(map && !done){
				if( map->l_name && * map->l_name ){
					unsigned int loadaddr = map->l_addr;

					/* 	LINUX PROBLEM. in the link_map structure the map->l_addr field is NOT
						the load address of the dynamic object, as the documentation says.  It is the
						RELOCATED address of the object. If the object was not relocated then the
						value is ZERO.

						So, on LINUX we check the address of the dynamic section, map->l_ld, which is
						correct.
					*/
#if defined(i386_unknown_linux2_0) || defined(x86_64_unknown_linux2_4)
					loadaddr = (unsigned long)map->l_ld;
#endif

					/*fprintf(stderr," CHECKING: %s %x\n",map->l_name, map->l_addr);*/
					diffAddr = checkSOLoadAddr(map->l_name, loadaddr);
					if(diffAddr){
						fixInstrumentation(map->l_name, loadaddr, diffAddr);
					}
#if defined(i386_unknown_linux2_0) \
 || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */
					/* ld-linux.so will never be hand relocated so l_addr should be correct. right? */
					if(strstr(map->l_name, "ld-linux.so")){
						ld_linuxBaseAddr = map->l_addr;
					}	
#endif
				}
				/* check every loaded SO but leave map such that map->l_next == NULL.
					The next time a SO is loaded it will be placed at 
					map->l_next, so keep a tail pointer such that we 
					dont need to loop through the entire list again
				*/
				if(map->l_next){
					map = map->l_next;
				}else{
					done = 1;
				}
			}
			if( shdr->sh_addr != 0){
				/* if the addr is zero, then there is 
					no PLT entry for dlopen.  if there is
					no entry for dlopen the mutatee must not
					call it.  -- what about calling it from
					a shared lib that is statically loaded?
				*/

			/* WHY IS THERE A POUND DEFINE HERE? 

				well, we need to intercept the dlopen calls from the mutated binary
				because our trampolines expect the shared libraries to be in
				a particular location and if they are not where they are expected
				our trampolines can jump off into nothingness, or even worse, some
				random bit of executable code.  

				So we must intercept the dlopen call and then check to be sure
				the shared libraries are loaded in the same place as before.  If
				they are not we exit with a message to the user saying this is
				a fatal error.
		
				Note, only shared libraries that have been instrumented are checked
				here.  
			*/

#if defined(sparc_sun_solaris2_4) 
			/* 
				For a description of what is going on here read
				the comment in dyninst_jump_template above.

				This code generated all the instructions refered
				to in that comment as "GENERATED BELOW".

			*/

			pltEntry = (unsigned int*) shdr->sh_addr;
			pltInsn = *pltEntry; /* save insn for later */
			pltEntry += 1;

			/* The PLT entry may look like:
				sethi
				ba,a
				nop

			   or
			
				sethi
				sethi
				jmp

			*/
			if( (*pltEntry & (BA_MASK)) == (BA_MASK) ){
				/* we have the sethi/ba,a/nop type */

				offset = (*pltEntry) & BA_IMM;
				if(offset & 0x00200000){
					/* negative so sign extend */
					offset = 0xffc00000 | offset;
				}
				PLTEntry = pltEntry;
			
				PLTEntry += (offset*4)/sizeof(PLTEntry); /* move PLTEntry offset*4 bytes!*/

			}else{
				/* we have the sethi/sethi/jmp type */
				tmpAddr = ((*pltEntry) & SETHI_IMM)<<10;
				pltEntry ++;
				tmpAddr += ((*pltEntry) & JMP_IMM);
				PLTEntry = (unsigned int *) tmpAddr;
				pltEntry --;
			}

			dyninst_jump_templatePtr = (unsigned int*) & __dyninst_jump_template__;

			baseAddr = ((unsigned int) dyninst_jump_templatePtr)  -
				( ((unsigned int) dyninst_jump_templatePtr)% getpagesize());
			size =  (unsigned int) dyninst_jump_templatePtr  - baseAddr + 80;
			result = mprotect((void*)baseAddr , size, 
                           PROT_READ|PROT_WRITE|PROT_EXEC);

			/* build sethi hi(register_o7), %g1 */
			*dyninst_jump_templatePtr = 0x03000000;
			*dyninst_jump_templatePtr |= ( (((unsigned int ) & register_o7)& 0xfffffc00) >> 10); /*0xffffe000 */

			dyninst_jump_templatePtr ++;

			/* build st %o7, &register_o7 */
			*dyninst_jump_templatePtr = 0xde206000;
			*dyninst_jump_templatePtr |=  ( ((unsigned int ) & register_o7) & 0x000003ff ); /*0x00001fff*/

			dyninst_jump_templatePtr ++;

			/* build call PLTEntry */
			*dyninst_jump_templatePtr = 0x40000000;
			*dyninst_jump_templatePtr |= ( ((unsigned int) (PLTEntry)-  ((unsigned int) dyninst_jump_templatePtr)) >>2);
			dyninst_jump_templatePtr ++;

			/* copy from plt */
			*dyninst_jump_templatePtr = pltInsn;
			dyninst_jump_templatePtr ++;


			/* advance past call to pseudoSigHandler */
			dyninst_jump_templatePtr = (unsigned int*) &__dyninst_jump_template__done__ ;
	
			/* build sethi hi(register_o7), %g1 */
			*dyninst_jump_templatePtr = 0x03000000;
			*dyninst_jump_templatePtr |= ( (((unsigned int ) & register_o7)& 0xfffffc00) >> 10); /*0xffffe000*/

			dyninst_jump_templatePtr ++;

			/* build ld %o7, register_o7 */
			*dyninst_jump_templatePtr = 0xde006000;
			*dyninst_jump_templatePtr |=  ( ((unsigned int ) & register_o7) & 0x000003ff );  /*0x00001fff*/


			/* THIS ENABLES THE JUMP */
			/* edit plt to jump to __dyninst_jump_template__ */
			baseAddr = ((unsigned int) pltEntry)  -
				( ((unsigned int) pltEntry)% getpagesize());
			size =  (unsigned int) pltEntry  - baseAddr + 8;
			result = mprotect((void*)baseAddr , size,
                           PROT_READ|PROT_WRITE|PROT_EXEC);

			/* build sethi hi(&__dyninst_jump_template__), %g1 */
			pltEntry --;
			*pltEntry = 0x03000000;
			*pltEntry |= ( (((unsigned int ) &__dyninst_jump_template__) )>> 10);
			pltEntry ++;
	
			/* build jmpl %g1, %r0 */	
			*pltEntry = 0x81c06000;
			*pltEntry |=  ( ((unsigned int ) &__dyninst_jump_template__ ) & 0x00003ff );

			pltEntry ++;
			*pltEntry = 0x01000000;
#elif defined(i386_unknown_linux2_0) \
   || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */
			/* install jump to catch call to _dl_debug_state */
			/* see comment int hack_ld_linux_plt for explainations */
			hack_ld_linux_plt(ld_linuxBaseAddr + shdr->sh_addr); 
#endif
		}/* shdr->sh_addr != 0 */ 
		}
		if( !strncmp((char *)strData->d_buf + shdr->sh_name, "dyninstAPIhighmem_",18)){
			/*the layout of dyninstAPIhighmem_ is:
			pageData
			address of update
			size of update
			...	
			address of update
			size of update	
			number of updates
	
			we must ONLY overwrite the updates, the other
			areas of the page may be important (and different than
			the saved data in the file.  we first copy out the
			page, the apply the updates to it, and then
			write it back.
			*/

			int oldPageDataSize;
			int count =0;

			retVal = 1; /* just to be sure */
			elfData = Elf_getdata(scn, NULL);
			numberUpdates = 0;
			
			/*this section may be padded out with zeros to align the next section
			  so we need to look backwards until we find a nonzero value */
			while(numberUpdates == 0){
				count++;
				numberUpdates = (unsigned int) ( ((unsigned int*) elfData->d_buf)[
					(elfData->d_size - (sizeof(unsigned int)*count))/ sizeof(unsigned int) ]);
			}

			/*fprintf(stderr," numberUpdates: %d :: (%d - 4) / 4  %x\n", numberUpdates, elfData->d_size, (unsigned int*) &elfData->d_buf );*/

			oldPageDataSize = shdr->sh_size-(((2*numberUpdates)* sizeof(unsigned int)) +((sizeof(unsigned int)*count))) ;


			oldPageData = (char*) malloc(oldPageDataSize+sizeof(unsigned long));
			/*fprintf(stderr,"oldpagedatasize %d datasize %d \n",oldPageDataSize,elfData->d_size);
			perror("malloc");*/
			/*copy old page data */


			/* probe memory to see if we own it */
#if defined(sparc_sun_solaris2_4)

			/* dladdr does not work here with all patchlevels of solaris 2.8
			   so we use the /proc file system to read in the /proc/pid/map file
			   and determine for our selves if the memory belongs to us yet or not*/
			findMap();
			checkAddr = checkMap((unsigned long)shdr->sh_addr);
#else
			checkAddr = dladdr((void*)shdr->sh_addr, &dlip);
#endif


			updateSize  = shdr->sh_size-((2*numberUpdates)* (sizeof(unsigned int)) -(count* (sizeof(unsigned int))));
			/*fprintf(stderr," updateSize : %d-((2 * %d + 1) * 4))",shdr->sh_size, numberUpdates);*/
	
			if(!checkAddr){ 
				/* we dont own it,mmap it!*/

                        	mmapAddr = shdr->sh_offset;
                        	mmapAddr =(unsigned long) mmap((void*) shdr->sh_addr,oldPageDataSize,
                                	PROT_READ|PROT_WRITE|PROT_EXEC,MAP_FIXED|MAP_PRIVATE,fd,mmapAddr);
					/*fprintf(stderr,"MMAP %x %d %x size: %x\n",shdr->sh_addr, mmapAddr,shdr->sh_offset,oldPageDataSize);*/
					

			}else{
				/*we own it, finish the memcpy */
				mmapAddr = (unsigned long) memcpy((void*) oldPageData, 
                                      (const void*) shdr->sh_addr, oldPageDataSize);
				/*fprintf(stderr,"memcpy %x %d\n",shdr->sh_addr, updateSize);*/

			}

			dataPtr =(unsigned long *) &(((char*)  elfData->d_buf)[oldPageDataSize]);	
			/*apply updates*/
			for(i = 0; i< numberUpdates; i++){
				updateAddress = *dataPtr; 
				updateSize = *(++dataPtr);

				updateOffset = updateAddress - shdr->sh_addr;
				/*do update*/	
				/*fprintf(stderr,"updateAddress %x : %x %x %d %d\n",updateAddress,&( oldPageData[updateOffset]), &(((char*)elfData->d_buf)[updateOffset]) , updateSize,updateOffset);*/
				memcpy(&( oldPageData[updateOffset]),
						&(((char*)elfData->d_buf)[updateOffset]) , updateSize);	

				dataPtr ++;

			
			} 
			if(!checkAddr){
				mmapAddr = shdr->sh_offset ;

				mmapAddr =(unsigned long) mmap((void*) shdr->sh_addr,oldPageDataSize, 
					PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED| MAP_PRIVATE,fd,mmapAddr);

					/*fprintf(stderr,"2MMAP %x %d\n",shdr->sh_addr, mmapAddr);*/


			}else{

				memcpy((void*) shdr->sh_addr, oldPageData,oldPageDataSize );
				/*fprintf(stderr,"2memcpy %x %d\n",shdr->sh_addr, oldPageDataSize);*/

			}
		}
		if(!strcmp((char *)strData->d_buf + shdr->sh_name, "dyninstAPI_loadLib")){
			/* ccw 14 may 2002 */
			/* this section loads shared libraries into the mutated binary
				that were loaded by BPatch_thread::loadLibrary */
			void * handle =NULL;
#if defined(sparc_sun_solaris2_4)
                        Dl_info p;
                        unsigned long loadAddr;
#endif
			elfData = Elf_getdata(scn, NULL);
			tmpPtr = elfData->d_buf;

			while(*tmpPtr) { 
				handle = dlopen(tmpPtr, RTLD_LAZY);
				if(handle){
#if defined(sparc_sun_solaris2_4)
					dlinfo(handle, RTLD_DI_CONFIGADDR,(void*) &p);
					loadAddr = checkSOLoadAddr(tmpPtr,(unsigned long)p.dli_fbase);
					if(loadAddr){
						fixInstrumentation(tmpPtr,(unsigned long)p.dli_fbase, loadAddr);
					}
#endif

				}else{

					printf(" %s cannot be loaded at the correct address\n", tmpPtr );
					printf(" This is an unrecoverable error, the instrumentation will not");
					printf("\n run correctly if shared libraries are loaded at a different address\n");
					printf("\n Exiting.....\n");

					printf("\n%s\n",dlerror());
					fflush(stdout);
					exit(9);

				}
                                /* brk ptr not used for ELF */
				tmpPtr += (strlen(tmpPtr) +1 + sizeof(void *));	

			}

		}
	}

#if defined(sparc_sun_solaris2_4)
	if(procMemMap){
		free(procMemMap);
	}
#endif

        Elf_end(elf);
        close(fd);

	free(execStr);

	if(soError){
		exit(2);
	}
	return retVal;
}
/* vim:set ts=5: */
