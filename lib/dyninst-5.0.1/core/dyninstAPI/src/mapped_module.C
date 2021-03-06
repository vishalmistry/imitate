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

// $Id: mapped_module.C,v 1.10.2.1 2006/09/19 16:07:14 legendre Exp $

#include "dyninstAPI/src/mapped_module.h"
#include "dyninstAPI/src/mapped_object.h"
#include "dyninstAPI/src/symtab.h"
#include "common/h/String.h"
#include "dyninstAPI/src/showerror.h"
#include "process.h"


const pdvector<int_function *> &mapped_module::getAllFunctions() {
    pdvector<image_func *> pdfuncs;
    internal_mod_->getFunctions(pdfuncs);
    if (everyUniqueFunction.size() == pdfuncs.size())
        return everyUniqueFunction;

    for (unsigned i = 0; i < pdfuncs.size(); i++) {
        // Will auto-create (and add to this module)
        obj()->findFunction(pdfuncs[i]);
    }
    assert(everyUniqueFunction.size() == pdfuncs.size());
    return everyUniqueFunction;
}

const pdvector<int_variable *> &mapped_module::getAllVariables() {
    pdvector<image_variable *> img_vars;
    internal_mod_->getVariables(img_vars);

    if (everyUniqueVariable.size() == img_vars.size())
        return everyUniqueVariable;

    for (unsigned i = 0; i < img_vars.size(); i++) {
        obj()->findVariable(img_vars[i]);
    }
    return everyUniqueVariable;
}

// We rely on the mapped_object for pretty much everything...
void mapped_module::addFunction(int_function *func) {
    // Just the everything vector... the by-name lists are
    // kept in the mapped_object and filtered if we do a lookup.
    everyUniqueFunction.push_back(func);
}

void mapped_module::addVariable(int_variable *var) {
    everyUniqueVariable.push_back(var);
}

const pdstring &mapped_module::fileName() const { 
    return pmod()->fileName(); 
}
const pdstring &mapped_module::fullName() const { 
    return pmod()->fullName(); 
}

mapped_object *mapped_module::obj() const { 
    return obj_;
}

bool mapped_module::isNativeCompiler() const {
    // This should probably be per-module info at some point; some
    // .o's might be compiled native, and others not.
    return pmod()->exec()->isNativeCompiler();
}

supportedLanguages mapped_module::language() const { 
    return pmod()->language(); 
}

bool mapped_module::findFuncVectorByMangled(const pdstring &funcname,
                                            pdvector<int_function *> &funcs)
{
    // For efficiency sake, we grab the image vector and strip out the
    // functions we want.
    // We could also keep them all in modules and ditch the image-wide search; 
    // the problem is that BPatch goes by module and internal goes by image. 
    unsigned orig_size = funcs.size();

    const pdvector<int_function *> *obj_funcs = obj()->findFuncVectorByMangled(funcname);
    if (!obj_funcs) {
        return false;
    }
    for (unsigned i = 0; i < obj_funcs->size(); i++) {
        if ((*obj_funcs)[i]->mod() == this)
            funcs.push_back((*obj_funcs)[i]);
    }
    return funcs.size() > orig_size;
}

bool mapped_module::findFuncVectorByPretty(const pdstring &funcname,
                                           pdvector<int_function *> &funcs)
{
    // For efficiency sake, we grab the image vector and strip out the
    // functions we want.
    // We could also keep them all in modules and ditch the image-wide search; 
    // the problem is that BPatch goes by module and internal goes by image. 
    unsigned orig_size = funcs.size();

    const pdvector<int_function *> *obj_funcs = obj()->findFuncVectorByPretty(funcname);
    if (!obj_funcs) return false;

    for (unsigned i = 0; i < obj_funcs->size(); i++) {
        if ((*obj_funcs)[i]->mod() == this)
            funcs.push_back((*obj_funcs)[i]);
    }
    return funcs.size() > orig_size;
}


pdmodule *mapped_module::pmod() const { return internal_mod_;}

void mapped_module::dumpMangled(pdstring prefix) const {
    // No reason to have this process specific... it just dumps
    // function names.
    pmod()->dumpMangled(prefix);
}

mapped_module::mapped_module(mapped_object *obj,
                             pdmodule *pdmod) :
    internal_mod_(pdmod),
    obj_(obj),
    lineInfoValid_(false)
{
}

mapped_module *mapped_module::createMappedModule(mapped_object *obj,
                                                 pdmodule *pdmod) {
    assert(obj);
    assert(pdmod);
    assert(pdmod->exec() == obj->parse_img());
    mapped_module *mod = new mapped_module(obj, pdmod);
    // Do things?

    return mod;
}

// BPatch loves the mapped_module, but we pass it up to the image (since
// that occupies a range of memory; modules can be scattered all around it).
codeRange *mapped_module::findCodeRangeByAddress(const Address &addr)  {
    return obj()->findCodeRangeByAddress(addr);
}

int_function *mapped_module::findFuncByAddr(const Address &addr)  {
    return obj()->findFuncByAddr(addr);
}


pdstring mapped_module::processDirectories(const pdstring &fn) const {
    // This is black magic... assume Todd (I think) knew what
    // he was doing....
	if(fn == "")
		return "";

	if(!strstr(fn.c_str(),"/./") &&
	   !strstr(fn.c_str(),"/../"))
            return fn;

	pdstring ret;
	char suffix[10] = "";
	char prefix[10] = "";
	char* pPath = new char[strlen(fn.c_str())+1];

	strcpy(pPath,fn.c_str());

	if(pPath[0] == '/')
           strcpy(prefix, "/");
	else
           strcpy(prefix, "");

	if(pPath[strlen(pPath)-1] == '/')
           strcpy(suffix, "/");
	else
           strcpy(suffix, "");

	int count = 0;
	char* pPathLocs[1024];
	char* p = strtok(pPath,"/");
	while(p){
		if(!strcmp(p,".")){
			p = strtok(NULL,"/");
			continue;
		}
		else if(!strcmp(p,"..")){
			count--;
			if(((count < 0) && (*prefix != '/')) || 
			   ((count >= 0) && !strcmp(pPathLocs[count],"..")))
			{
				count++;
				pPathLocs[count++] = p;
			}
			if(count < 0) count = 0;
		}
		else
			pPathLocs[count++] = p;

		p = strtok(NULL,"/");
	}

	ret += prefix;
	for(int i=0;i<count;i++){
		ret += pPathLocs[i];
		if(i != (count-1))
			ret += "/";
	}
	ret += suffix;

	delete[] pPath;
	return ret;
}

process *mapped_module::proc() const { return obj()->proc(); }


// Line information is processed for all modules in an image at once; so we have to do
// them at the same time. For now we're process-specific processing them. This code
// can move (back) into symtab.C if there is a mechanism for a process-specific
// line information structure.


///////////////////////////////////////////
// ABANDON ALL HOPE YE WHO READ PAST HERE
///////////////////////////////////////////


// Parses symtab for file and line info. Should not be called before
// parseTypes. The ptr to lineInformation should be NULL before this is called.
#if !defined(rs6000_ibm_aix4_1) \
 && !defined(mips_sgi_irix6_4) \
 && !defined(alpha_dec_osf4_0) \
 && !defined(i386_unknown_nt4_0) \
 && !defined( USES_DWARF_DEBUG )
 
/* Parse everything in the file on disk, and cache that we've done so,
   because our modules may not bear any relation to the name source files. */
void mapped_module::parseFileLineInfo() {
	static dictionary_hash< pdstring, bool > haveParsedFileMap( pdstring::hash );
	
	image * fileOnDisk = obj()->parse_img();
	assert( fileOnDisk != NULL );
	const Object & elfObject = fileOnDisk->getObject();

	const char * fileName = elfObject.getFileName();
	if( haveParsedFileMap.defines( fileName ) ) { return; } 

	/* We haven't parsed this file already, so iterate over its stab entries. */
	stab_entry * stabEntry = elfObject.get_stab_info();
	assert( stabEntry != NULL );
	const char * nextStabString = stabEntry->getStringBase();
	
	const char * currentSourceFile = NULL;
	mapped_module * currentModule = NULL;
	Address currentFunctionBase = 0;
	unsigned int previousLineNo = 0;
	Address previousLineAddress = 0;
	bool isPreviousValid = false;
	
	Address baseAddress = obj()->codeBase();
	
	for( unsigned int i = 0; i < stabEntry->count(); i++ ) {
		switch( stabEntry->type( i ) ) {
		
			case N_UNDF: /* start of an object file */ {
				if( isPreviousValid ) {
					/* DEBUG */ fprintf( stderr, "%s[%d]: unterminated N_SLINE at start of object file.  Line number information will be lost.\n", __FILE__, __LINE__ );
					}
			
				stabEntry->setStringBase( nextStabString );
				nextStabString = stabEntry->getStringBase() + stabEntry->val( i );
				
				currentSourceFile = NULL;
				isPreviousValid = false;
				} break;
				
			case N_SO: /* compilation source or file name */ {
				if( isPreviousValid ) {
					/* Add the previous N_SLINE. */
					Address currentLineAddress = stabEntry->val( i );
					
					// /* DEBUG */ fprintf( stderr, "%s[%d]: adding %s:%d [0x%lx, 0x%lx) to module %s.\n", __FILE__, __LINE__, currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress, currentModule->fileName().c_str() );
					currentModule->lineInfo_.addLine( currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress  );
					}
				
				const char * sourceFile = stabEntry->name( i );
				currentSourceFile = strrchr( sourceFile, '/' );
				if( currentSourceFile == NULL ) { currentSourceFile = sourceFile; }
				else { ++currentSourceFile; }
				// /* DEBUG */ fprintf( stderr, "%s[%d]: using file name '%s'\n", __FILE__, __LINE__, currentSourceFile );
				
				isPreviousValid = false;
				} break;
				
			case N_SOL: /* file name (possibly an include file) */ {
				if( isPreviousValid ) {
					/* Add the previous N_SLINE. */
					Address currentLineAddress = stabEntry->val( i );
					// /* DEBUG */ fprintf( stderr, "%s[%d]: adding %s:%d [0x%lx, 0x%lx) to module %s.\n", __FILE__, __LINE__, currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress, currentModule->fileName().c_str() );
					currentModule->lineInfo_.addLine( currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress  );
					}
					
				const char * sourceFile = stabEntry->name( i );
				currentSourceFile = strrchr( sourceFile, '/' );
				if( currentSourceFile == NULL ) { currentSourceFile = sourceFile; }
				else { ++currentSourceFile; }
				// /* DEBUG */ fprintf( stderr, "%s[%d]: using file name '%s'\n", __FILE__, __LINE__, currentSourceFile );
				
				isPreviousValid = false;
				} break;
				
			case N_FUN: /* a function */ {
				if( * stabEntry->name( i ) == 0 ) {
					/* An end-of-function marker.  The value is the size of the function. */
					if( isPreviousValid ) {
						/* Add the previous N_SLINE. */
						Address currentLineAddress = currentFunctionBase + stabEntry->val( i );
						// /* DEBUG */ fprintf( stderr, "%s[%d]: adding %s:%d [0x%lx, 0x%lx) in module %s.\n", __FILE__, __LINE__, currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress, currentModule->fileName().c_str() );
						currentModule->lineInfo_.addLine( currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress  );
						}
					
					/* We've added the previous N_SLINE and don't currently have a module. */
					isPreviousValid = false;
					currentModule = NULL;
					break;
					} /* end if the N_FUN is an end-of-function-marker. */
							
				if( isPreviousValid ) {
					Address currentLineAddress = stabEntry->val( i );
					// /* DEBUG */ fprintf( stderr, "%s[%d]: adding %s:%d [0x%lx, 0x%lx) in module %s.\n", __FILE__, __LINE__, currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress, currentModule->fileName().c_str() );
					currentModule->lineInfo_.addLine( currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress  );
					}
					
				currentFunctionBase = stabEntry->val( i );
				currentFunctionBase += baseAddress;
				
				int_function * currentFunction = obj()->findFuncByAddr( currentFunctionBase );
				if( currentFunction == NULL ) {
                                    // /* DEBUG */ fprintf( stderr, "%s[%d]: failed to find function containing address 0x%lx; line number information will be lost.\n", __FILE__, __LINE__, currentFunctionBase );
					currentModule = NULL;
					}
				else {
					currentModule = currentFunction->mod();
					assert( currentModule != NULL );
					}
											
				isPreviousValid = false;
				} break;
				
			case N_SLINE: {
				if( currentModule ) {
					Address currentLineAddress = currentFunctionBase + stabEntry->val( i );
					unsigned int currentLineNo = stabEntry->desc( i );
					
					if( isPreviousValid ) {
						// /* DEBUG */ fprintf( stderr, "%s[%d]: adding %s:%d [0x%lx, 0x%lx) in module %s.\n", __FILE__, __LINE__, currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress, currentModule->fileName().c_str() );
						currentModule->lineInfo_.addLine( currentSourceFile, previousLineNo, previousLineAddress, currentLineAddress  );
						}
						
					previousLineAddress = currentLineAddress;
					previousLineNo = currentLineNo;
					isPreviousValid = true;
					} /* end if we've a module to which to add line information */
				} break;
						
			} /* end switch on the ith stab entry's type */
		} /* end iteration over stab entries. */
	
	haveParsedFileMap[ fileName ] = true;
	} /* end parseFileLineInfo() */
	
#endif 



#if defined(rs6000_ibm_aix4_1)

#include <linenum.h>
#include <syms.h>
#include <set>

/* FIXME: hack. */
Address trueBaseAddress = 0;

void mapped_module::parseFileLineInfo() {
	static std::set< image * > haveParsedFileMap;
	
   image * fileOnDisk = obj()->parse_img();
	assert( fileOnDisk != NULL );
	if( haveParsedFileMap.count( fileOnDisk ) != 0 ) { return; }
	// /* DEBUG */ fprintf( stderr, "%s[%d]: Considering image at 0x%lx\n", __FILE__, __LINE__, fileOnDisk );

	/* FIXME: hack.  Should be argument to parseLineInformation(), which should in turn be merged
	   back into here so it can tell how far to extend the range of the last line information point. */
	Address baseAddress = obj()->codeBase();

	trueBaseAddress = baseAddress;

	const Object & xcoffObject = fileOnDisk->getObject();

	/* We haven't parsed this file already, so iterate over its stab entries. */
	char * stabstr = NULL;
	int nstabs = 0;
	SYMENT * syms = 0;
	char * stringpool = NULL;
	xcoffObject.get_stab_info( stabstr, nstabs, syms, stringpool );

	int nlines = 0;
	char * lines = NULL;
	unsigned long linesfdptr;
	xcoffObject.get_line_info( nlines, lines, linesfdptr );

	/* I'm not sure why the original code thought it should copy (short) names (through here). */
	char temporaryName[256];
	char * funcName = NULL;
	char * currentSourceFile = NULL;
   char *moduleName = NULL;

	/* Iterate over STAB entries. */
	for( int i = 0; i < nstabs; i++ ) {
		/* sizeof( SYMENT ) is 20, not 18, as it should be. */
		SYMENT * sym = (SYMENT *)( (unsigned)syms + (i * SYMESZ) );

      /* Get the name (period) */
      if (!sym->n_zeroes) {
         moduleName = &stringpool[sym->n_offset];
      } else {
         memset(temporaryName, 0, 9);
         strncpy(temporaryName, sym->n_name, 8);
         moduleName = temporaryName;
      }

	
		/* Extract the current source file from the C_FILE entries. */
		if( sym->n_sclass == C_FILE ) {
         if (!strcmp(moduleName, ".file")) {
            // The actual name is in an aux record.

            int j;
            /* has aux record with additional information. */
            for (j=1; j <= sym->n_numaux; j++) {
               union auxent *aux = (union auxent *) ((char *) sym + j * SYMESZ);
               if (aux->x_file._x.x_ftype == XFT_FN) {
                  // this aux record contains the file name.
                  if (!aux->x_file._x.x_zeroes) {
                     moduleName = &stringpool[aux->x_file._x.x_offset];
                  } else {
                     // x_fname is 14 bytes
                     memset(temporaryName, 0, 15);
                     strncpy(temporaryName, aux->x_file.x_fname, 14);
                     moduleName = temporaryName;
                  }
               }
            }
         }
			
         currentSourceFile = strrchr( moduleName, '/' );
         if( currentSourceFile == NULL ) { currentSourceFile = moduleName; }
         else { ++currentSourceFile; }
                    
         /* We're done with this entry. */
         continue;
      } /* end if C_FILE */
	
		/* This apparently compensates for a bug in the naming of certain entries. */
		char * nmPtr = NULL;
		if( 	! sym->n_zeroes && (
                                ( sym->n_sclass & DBXMASK ) ||
                                ( sym->n_sclass == C_BINCL ) ||
                                ( sym->n_sclass == C_EINCL )
                                ) ) {
			if( sym->n_offset < 3 ) {
				if( sym->n_offset == 2 && stabstr[ 0 ] ) {
					nmPtr = & stabstr[ 0 ];
            } else {
					nmPtr = & stabstr[ sym->n_offset ];
            }
         } else if( ! stabstr[ sym->n_offset - 3 ] ) {
				nmPtr = & stabstr[ sym->n_offset ];
         } else {
				/* has off by two error */
				nmPtr = & stabstr[ sym->n_offset - 2 ];
         } 
      } else {
			// names 8 or less chars on inline, not in stabstr
			memset( temporaryName, 0, 9 );
			strncpy( temporaryName, sym->n_name, 8 );
			nmPtr = temporaryName;
      } /* end bug compensation */

		/* Now that we've compensated for buggy naming, actually
		   parse the line information. */
		if(	( sym->n_sclass == C_BINCL ) 
            || ( sym->n_sclass == C_EINCL )
            || ( sym->n_sclass == C_FUN ) ) {
			if( funcName ) {
				free( funcName );
				funcName = NULL;
         }
			funcName = strdup( nmPtr );

			pdstring pdCSF( currentSourceFile );
			parseLineInformation( proc(), & pdCSF, funcName, (SYMENT *)sym, linesfdptr, lines, nlines );
      } /* end if we're actually parsing line information */
   } /* end iteration over STAB entries. */

	if( funcName != NULL ) { 
		free( funcName );
   }		
	haveParsedFileMap.insert( fileOnDisk );
} /* end parseFileLineInfo() */

void mapped_module::parseLineInformation(process * /* proc */,
                                         pdstring * currentSourceFile,
                                         char * symbolName,
                                         SYMENT * sym,
                                         Address linesfdptr,
                                         char * lines,
                                         int nlines ) {
    union auxent * aux;
    pdvector<IncludeFileInfo> includeFiles;
    
    /* if it is beginning of include files then update the data structure
       that keeps the beginning of the include files. If the include files contain
       information about the functions and lines we have to keep it */
    if( sym->n_sclass == C_BINCL ) {
        includeFiles.push_back( IncludeFileInfo( (sym->n_value - linesfdptr)/LINESZ, symbolName ) );
    }
    /* similiarly if the include file contains function codes and line information
       we have to keep the last line information entry for this include file */
    else if( sym->n_sclass == C_EINCL ) {
        if( includeFiles.size() > 0 ) {
            includeFiles[includeFiles.size()-1].end = (sym->n_value-linesfdptr)/LINESZ;
        }
    }
    /* if the enrty is for a function than we have to collect all info
       about lines of the function */
    else if( sym->n_sclass == C_FUN ) {
        /* I have no idea what the old code did, except not work very well.
           Somebody who understands XCOFF should look at this. */
        int initialLine = 0;
        int initialLineIndex = 0;
        Address funcStartAddress = 0;
        Address funcEndAddress = 0;
        
        for( int j = -1; ; --j ) {
            SYMENT * extSym = (SYMENT *)( ((Address)sym) + (j * SYMESZ) );
            if( extSym->n_sclass == C_EXT || extSym->n_sclass == C_HIDEXT ) {
                aux = (union auxent *)( ((Address)extSym) + SYMESZ );
#ifndef __64BIT__
                initialLineIndex = ( aux->x_sym.x_fcnary.x_fcn.x_lnnoptr - linesfdptr )/LINESZ;
#endif
                funcStartAddress = extSym->n_value;
                break;
            } /* end if C_EXT found */
        } /* end search for C_EXT */
        
        /* access the line information now using the C_FCN entry*/
        SYMENT * bfSym = (SYMENT *)( ((Address)sym) + SYMESZ );
        if( bfSym->n_sclass != C_FCN ) {
            bperr("unable to process line info for %s\n", symbolName);
            return;
        }
        SYMENT * efSym = (SYMENT *)( ((Address)bfSym) + (2 * SYMESZ) );
        while (efSym->n_sclass != C_FCN)
           efSym = (SYMENT *) ( ((Address)efSym) + SYMESZ );
        funcEndAddress = efSym->n_value;
        
        aux = (union auxent *)( ((Address)bfSym) + SYMESZ );
        initialLine = aux->x_sym.x_misc.x_lnsz.x_lnno;
        
        pdstring whichFile = *currentSourceFile;
        for( unsigned int j = 0; j < includeFiles.size(); j++ ) {
            if(	( includeFiles[j].begin <= (unsigned)initialLineIndex )
            	&& ( includeFiles[j].end >= (unsigned)initialLineIndex ) ) {
                whichFile = includeFiles[j].name;
                break;
            }
        } /* end iteration of include files */
        
        int_function * currentFunction = obj()->findFuncByAddr( funcStartAddress + trueBaseAddress );
        if( currentFunction == NULL ) {
            /* Some addresses point to gdb-inaccessible memory; others have symbols (gdb will disassemble them)
               but the contents look like garbage, and may be data with symbol names.  (Who knows why.) */
            // fprintf( stderr, "%s[%d]: failed to find function containing address 0x%lx; line number information will be lost.\n", __FILE__, __LINE__, funcStartAddress + trueBaseAddress );
            return;
        }
        mapped_module * currentModule = currentFunction->mod();
        assert( currentModule != NULL );
        LineInformation & currentLineInformation = currentModule->lineInfo_;
        
        unsigned int previousLineNo = 0;
        Address previousLineAddr = 0;
        bool isPreviousValid = false;
        
        /* Iterate over this entry's lines. */
        for( int j = initialLineIndex + 1; j < nlines; j++ ) {
            LINENO * lptr = (LINENO *)( lines + (j * LINESZ) );
            if( ! lptr->l_lnno ) { break; }
            unsigned int lineNo = lptr->l_lnno + initialLine - 1;
            Address lineAddr = lptr->l_addr.l_paddr + trueBaseAddress;
            
            if( isPreviousValid ) {
                // /* DEBUG */ fprintf( stderr, "%s[%d]: adding %s:%d [0x%lx, 0x%lx).\n", __FILE__, __LINE__, whichFile.c_str(), previousLineNo, previousLineAddr, lineAddr );
                currentLineInformation.addLine( whichFile.c_str(), previousLineNo, previousLineAddr, lineAddr );
            }
            
            previousLineNo = lineNo;
            previousLineAddr = lineAddr;
            isPreviousValid = true;
        } /* end iteration over line information */
        
        if( isPreviousValid ) {
            /* Add the instruction (always 4 bytes on power) pointed at by the last entry.  We'd like to add a
               bigger range, but it's not clear how.  (If the function has inlined code, we won't know about
               it until we see the next section, so claiming "until the end of the function" will give bogus results.) */
            // /* DEBUG */ fprintf( stderr, "%s[%d]: adding %s:%d [0x%lx, 0x%lx).\n", __FILE__, __LINE__, whichFile.c_str(), previousLineNo, previousLineAddr, previousLineAddr + 4 );
           while (previousLineAddr < funcEndAddress) {
            currentLineInformation.addLine( whichFile.c_str(), previousLineNo, previousLineAddr, previousLineAddr + 4 );
            previousLineAddr += 4;
           }
        }
    } /* end if we found a C_FUN symbol */
} /* end parseLineInformation() */

#endif

/* mips-sgi-irix6.5 uses DWARF debug, but the rest of the code
   isn't set up to take advantage of this. */
#if defined(USES_DWARF_DEBUG) && !defined(mips_sgi_irix6_4)

#include "elf.h"
#include "libelf.h"
#include "dwarf.h"
#include "libdwarf.h"  

#include "LineInformation.h"

extern void pd_dwarf_handler( Dwarf_Error, Dwarf_Ptr );
void mapped_module::parseFileLineInfo() {
	/* Determine if we've parsed this file already. */
	image * moduleImage = obj()->parse_img();
	assert( moduleImage != NULL );
	const Object & moduleObject = moduleImage->getObject();	
	const char * fileName = moduleObject.getFileName();

	/* We have not parsed this file already, so wind up libdwarf. */
	int fd = open( fileName, O_RDONLY );
   if (fd == -1)
      return;
	
	Dwarf_Debug dbg;
	int status = dwarf_init(	fd, DW_DLC_READ, & pd_dwarf_handler,
								moduleObject.getErrFunc(),
								& dbg, NULL );
	if( status != DW_DLV_OK ) { P_close( fd ); return; }
	
	/* Itereate over the CU headers. */
	Dwarf_Unsigned header;
	while( dwarf_next_cu_header( dbg, NULL, NULL, NULL, NULL, & header, NULL ) == DW_DLV_OK ) {
		/* Acquire the CU DIE. */
		Dwarf_Die cuDIE;
		status = dwarf_siblingof( dbg, NULL, & cuDIE, NULL);
		if( status != DW_DLV_OK ) { 
			/* If we can get no (more) CUs, we're done. */
			break;
			}
		
		/* Acquire this CU's source lines. */
		Dwarf_Line * lineBuffer;
		Dwarf_Signed lineCount;
		status = dwarf_srclines( cuDIE, & lineBuffer, & lineCount, NULL );
		
		/* See if we can get anything useful out of the next CU
		   if this one is corrupt. */
		if( status == DW_DLV_ERROR ) {
			dwarf_printf( "%s[%d]: dwarf_srclines() error.\n" );
			}
		
		/* It's OK for a CU not to have line information. */
		if( status != DW_DLV_OK ) {
			/* Free this CU's DIE. */
			dwarf_dealloc( dbg, cuDIE, DW_DLA_DIE );
			continue;
			}
		assert( status == DW_DLV_OK );
		
		/* The 'lines' returned are actually interval markers; the code
		   generated from lineNo runs from lineAddr up to but not including
		   the lineAddr of the next line. */			   
		bool isPreviousValid = false;
		Dwarf_Unsigned previousLineNo = 0;
		Dwarf_Addr previousLineAddr = 0x0;
		char * previousLineSource = NULL;
		
		Address baseAddr = obj()->codeBase();
		
		/* Iterate over this CU's source lines. */
		for( int i = 0; i < lineCount; i++ ) {
			/* Acquire the line number, address, source, and end of sequence flag. */
			Dwarf_Unsigned lineNo;
			status = dwarf_lineno( lineBuffer[i], & lineNo, NULL );
			if( status != DW_DLV_OK ) { continue; }
				
			Dwarf_Addr lineAddr;
			status = dwarf_lineaddr( lineBuffer[i], & lineAddr, NULL );
			if( status != DW_DLV_OK ) { continue; }
			lineAddr += baseAddr;
			
			char * lineSource;
			status = dwarf_linesrc( lineBuffer[i], & lineSource, NULL );
			if( status != DW_DLV_OK ) { continue; }
						
			Dwarf_Bool isEndOfSequence;
			status = dwarf_lineendsequence( lineBuffer[i], & isEndOfSequence, NULL );
			if( status != DW_DLV_OK ) { continue; }
			
			if( isPreviousValid ) {
				/* If we're talking about the same (source file, line number) tuple,
				   and it isn't the end of the sequence, we can coalesce the range.
				   (The end of sequence marker marks discontinuities in the ranges.) */
				if( lineNo == previousLineNo && strcmp( lineSource, previousLineSource ) == 0 && ! isEndOfSequence ) {
					/* Don't update the prev* values; just keep going until we hit the end of a sequence or
					   a new sourcefile. */
					continue;
					} /* end if we can coalesce this range */
                                
				/* Determine into which mapped_module this line information should be inserted. */
				int_function * currentFunction = obj()->findFuncByAddr( previousLineAddr );
				if( currentFunction == NULL ) {
					// /* DEBUG */ fprintf( stderr, "%s[%d]: failed to find function containing address 0x%lx; line number information will be lost.\n", __FILE__, __LINE__, lineAddr );
					}
				else {
					mapped_module * currentModule = currentFunction->mod();
					assert( currentModule != NULL );
					
					char * canonicalLineSource = strrchr( previousLineSource, '/' );
					if( canonicalLineSource == NULL ) { canonicalLineSource = previousLineSource; }
					else { ++canonicalLineSource; }
					
					/* The line 'canonicalLineSource:previousLineNo' has an address range of [previousLineAddr, lineAddr). */
					currentModule->lineInfo_.addLine( canonicalLineSource, previousLineNo, previousLineAddr, lineAddr );
				
					// /* DEBUG */ fprintf( stderr, "%s[%d]: inserted address range [0x%lx, 0x%lx) for source '%s:%u' into module '%s'.\n", __FILE__, __LINE__, previousLineAddr, lineAddr, canonicalLineSource, previousLineNo, currentModule->fileName().c_str() );
					} /* end if we found the function by its address */
				} /* end if the previous* variables are valid */
				
			/* If the current line ends the sequence, invalidate previous; otherwise, update. */
			if( isEndOfSequence ) {
				dwarf_dealloc( dbg, lineSource, DW_DLA_STRING );
				
				isPreviousValid = false;
				}
			else {
				if( isPreviousValid ) { dwarf_dealloc( dbg, previousLineSource, DW_DLA_STRING ); }

				previousLineNo = lineNo;
				previousLineSource = lineSource;
				previousLineAddr = lineAddr;
							
				isPreviousValid = true;
				} /* end if line was not the end of a sequence */
			} /* end iteration over source line entries. */
		
		/* Free this CU's source lines. */
		for( int i = 0; i < lineCount; i++ ) {
			dwarf_dealloc( dbg, lineBuffer[i], DW_DLA_LINE );
			}
		dwarf_dealloc( dbg, lineBuffer, DW_DLA_LIST );
		
		/* Free this CU's DIE. */
		dwarf_dealloc( dbg, cuDIE, DW_DLA_DIE );
		} /* end CU header iteration */

	/* Wind down libdwarf. */
	status = dwarf_finish( dbg, NULL );
	if( status != DW_DLV_OK ) {
		dwarf_printf( "%s[%d]: failed to dwarf_finish()\n" );
		}
	P_close( fd );
	
	/* Note that we've parsed this file. */
	} /* end parseFileLineInfo() */
#elif defined(arch_alpha)
void mapped_module::parseFileLineInfo() {
    // We don't do anything here

}
#elif defined(os_windows)
//void mapped_module::parseFileLineInfo() {
// Or here, I believe
//}
#endif


LineInformation &mapped_module::getLineInformation() {
    if (!lineInformation()) {
        parseFileLineInfo();
        lineInfoValid_ = true;
    }
    return lineInfo_;
}


