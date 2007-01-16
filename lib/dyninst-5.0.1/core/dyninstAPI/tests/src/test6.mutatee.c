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

/* $Id: test6.mutatee.c,v 1.30 2006/05/03 00:31:24 jodom Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define dprintf	if (debugPrint) printf
int debugPrint = 0;

#define MAX_TEST 8

int runTest[MAX_TEST+1];
int passedTest[MAX_TEST+1];

#define TRUE	1
#define FALSE	0

#define USAGE "Usage: test6.mutatee [-verbose] -run <num> .."

/*
 * Verify that a scalar value of a variable is what is expected
 *
 */
void verifyScalarValue(const char *name, int a, int value, int testNum, 
                       const char *testName)
{
    if (a != value) {
	if (passedTest[testNum])
	    printf("**Failed** test %d (%s)\n", testNum, testName);
	printf("  %s = %d, not %d\n", name, a, value);
	passedTest[testNum] = FALSE;
    }
}

extern long loadsnstores(long, long, long); /* ILP32 & LP64 */
int result_of_loadsnstores;

unsigned int loadCnt = 0;
unsigned int storeCnt = 0;
unsigned int prefeCnt = 0;
unsigned int accessCnt = 0;

unsigned int accessCntEA = 0;
unsigned int accessCntBC = 0;
int doomEA = 0;
int doomBC = 0;
void* eaList[1000];
unsigned int bcList[1000];
void* eaExp[1000];

unsigned int accessCntEAcc = 0;
unsigned int accessCntBCcc = 0;
int doomEAcc = 0;
int doomBCcc = 0;
void* eaListCC[1000];
unsigned int bcListCC[1000];
void* eaExpCC[1000];
unsigned int bcExpCC[1000];

#ifdef sparc_sun_solaris2_4
/* const */ unsigned int loadExp=15;
/* const */ unsigned int storeExp=13;
/* const */ unsigned int prefeExp=2;
/* const */ unsigned int accessExp=26;
/* const */ unsigned int accessExpCC=26;

unsigned int bcExp[] = { 4,1,2,8,4,1,1,  4,8,4,  4,4,8,8,16,
                         0,0,  1,2,4,8,  4,8,16,4,8 };

int eaExpOffset[] =    { 0,3,2,0,0,3,3,  0,0,0,  0,0,0,0,0,
                         0,0,  7,6,4,0,  0,0,0,4,0 };


extern void* eaExp[]; /* forward */
extern int divarw;
extern float dfvars;
extern double dfvard;
extern long double dfvarq;

/* _inline */ void init_test_data()
{
  int i=0;

  /*
  printf("&divarw = %p\n", &divarw);
  printf("&dfvars = %p\n", &dfvars);
  printf("&dfvard = %p\n", &dfvard);
  printf("&dfvarq = %p\n", &dfvarq);
  */

  for(; i<10; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);

  for(; i<12; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);

  for(; i<14; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvard + eaExpOffset[i]);

  for(; i<17; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvarq + eaExpOffset[i]);

  for(; i<21; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);

  eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);
  ++i;

  eaExp[i] = (void*)((unsigned long)&dfvard + eaExpOffset[i]);
  ++i;

  eaExp[i] = (void*)((unsigned long)&dfvarq + eaExpOffset[i]);
  ++i;

  for(; i<26; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);

  /* Duplicate the stream for cc */
  for(i=0; i<accessExp; ++i) {
    eaExpCC[i] = eaExp[i];
    bcExpCC[i] = bcExp[i];
  }
}
#endif

#ifdef rs6000_ibm_aix4_1
const unsigned int loadExp=41;
const unsigned int storeExp=32;
const unsigned int prefeExp=0;
const unsigned int accessExp=73;
const unsigned int accessExpCC=73;

unsigned int bcExp[] = { 4,  1,1,1,1,  2,2,2,2,  2,2,2,2,  4,4,4,4,
			 4,4,4,  8,8,8,8,  1,1,1,1,  2,2,2,2,
			 4,4,4,4,  8,8,8,8,  2,4,2,4,  76,76,24,20,
			 20,20,  4,4,8,8,  4,  4,4,4,4,  4,  8,8,8,8,
			 4,4,4,4,  8,8,8,8,  4 };

int eaExpOffset[] =    { 0, 17,3,1,2,  0,4,2,0,  2,2,2,2,  0,4,4,4,
			 4,12,2,  0,0,0,0,  3,1,1,1,  2,6,2,2,
			 0,4,4,4,  0,0,0,0,  0,0,0,0,  -76,-76,-24,-24,
			 -20,-20,    0,0,0,0,  0,  0,4,0,4,  0,  0,8,8,8,
			 4,4,0,0,  0,8,8,8,  0 };

extern void* eaExp[]; /* forward */
extern int divarw;
extern float dfvars;
extern double dfvard;

extern void* gettoc();
extern void* getsp();

#ifdef __GNUC__
#define _inline inline
#endif

/* _inline */ void init_test_data()
{
  int i;

  void *toc = gettoc();
  void *sp  = getsp(1,2,3);

  dprintf("&divarw = %p\n", &divarw);
  dprintf("&dfvars = %p\n", &dfvars);
  dprintf("&dfvard = %p\n", &dfvard);

  dprintf("toc = %p\n", toc);
  dprintf("sp = %p\n", sp);

  eaExp[0] = toc; /* assuming that TOC entries are not reordered */

  for(i=1; i<44; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);

  for(i=44; i<50; ++i)
    eaExp[i] = (void*)((unsigned long)sp + eaExpOffset[i]);; /* SP */
  
  for(i=50; i<54; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);

  eaExp[54] = (void*)((unsigned long)toc + sizeof(void*)); /* TOC */

  for(i=55; i<59; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);

  eaExp[59] = (void*)((unsigned long)toc + 2*sizeof(void*)); /* TOC */

  for(i=60; i<64; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvard + eaExpOffset[i]);

  for(i=64; i<68; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);

  for(i=68; i<72; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvard + eaExpOffset[i]);
  
  eaExp[72] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);


  /* Duplicate the stream for cc */
  for(i=0; i<accessExp; ++i) {
    eaExpCC[i] = eaExp[i];
    bcExpCC[i] = bcExp[i];
  }
}
#endif

#if defined(i386_unknown_linux2_0) \
 || defined(i386_unknown_nt4_0)
unsigned int loadExp=65;
unsigned int storeExp=23;
unsigned int prefeExp=2;
unsigned int accessExp=88;
unsigned int accessExpCC=87;

struct reduction {
  unsigned int loadRed;
  unsigned int storeRed;
  unsigned int prefeRed;
  unsigned int axsRed;
  unsigned int axsShift;
};

const struct reduction mmxRed = { 2, 1, 0, 3, 48 };
const struct reduction sseRed = { 2, 0, 1, 3, 51 };
const struct reduction sse2Red = { 2, 0, 0, 2, 54 };
const struct reduction amdRed = { 2, 0, 1, 3, 56 };

const struct reduction ccRed = { 0, 0, 0, 1, 83 };

int eaExpOffset[] =    { 0,0,0,0,  0,0,0,0,0,0,0,  4,8,4,8,4,8,4,  0,
                         0,4,8,12,0,4,8,  12,0,8,8,8,0,4,8,4,  0,  4,4,4,0,4,0,4,8,0,0,4,0,
                         0,8,0,  0,0,0,  0,0,  0,8,0,  0,12,0,0,0,44,25,   0,0,0,0,4,8,
                         0,0,0,2,4,8,  0,0,  0,0,  0,4,8 };

extern void* eaExp[]; /* forward */

unsigned int bcExp[] = { 4,4,4,4,  4,4,4,4,4,4,4,  4,4,4,4,4,4,4,  4,
                         4,4,4,4,4,4,4,   4,4,4,4,4,4,4,4,4,   4,  4,4,1,1,4,4,4,4,4,1,4,4,
                         4,8,8,  16,4,0, 16,8, 8,8,0,  12,4,16,16,49,4,4,  4,8,10,2,4,8,
                         4,8,10,2,4,8, 2,2,  28,28,  4,4,4,  4,4,4 };

extern int ia32features();
extern int amd_features();

extern int divarw;
extern float dfvars;
extern double dfvard;
extern long double dfvart; /* 10 byte hopefully, but it shouldn't matter... */
extern unsigned char dlarge[512];

#define CAP_MMX   (1<<23)
#define CAP_SSE   (1<<25)
#define CAP_SSE2  (1<<26)
#define CAP_3DNOW (1<<31)

void reduce(const struct reduction x)
{
  unsigned int i;

  loadExp  -= x.loadRed;
  storeExp -= x.storeRed;
  prefeExp -= x.prefeRed;

  for(i=x.axsShift; i<accessExp; ++i)
    eaExp[i] = eaExp[i+x.axsRed];

  for(i=x.axsShift; i<accessExp; ++i)
    bcExp[i] = bcExp[i+x.axsRed];

  for(i=x.axsShift; i<accessExpCC; ++i)
    eaExpCC[i] = eaExpCC[i+x.axsRed];

  for(i=x.axsShift; i<accessExpCC; ++i)
    bcExpCC[i] = bcExpCC[i+x.axsRed];

  accessExp -= x.axsRed;
  accessExpCC -= x.axsRed;
}

void reduceCC(const struct reduction x)
{
  unsigned int i;

  for(i=x.axsShift; i<accessExpCC; ++i)
    eaExpCC[i] = eaExpCC[i+x.axsRed];

  for(i=x.axsShift; i<accessExpCC; ++i)
    bcExpCC[i] = bcExpCC[i+x.axsRed];

  accessExpCC -= x.axsRed;
}


void init_test_data()
{
  int caps;
  unsigned int i;

  dprintf("&divarw = %p\n", &divarw);
  dprintf("&dfvars = %p\n", &dfvars);
  dprintf("&dfvard = %p\n", &dfvard);
  dprintf("&dfvart = %p\n", &dfvart);
  dprintf("&dlarge = %p\n", &dlarge);

  for(i=4; i<15; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]); /* skip ebp for now */
  for(i=16; i<18; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  for(i=19; i<26; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  i=26;
  eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  for(i=28; i<35; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  for(i=36; i<51; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  for(i=51; i<53; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);
  i=53;
  eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  for(i=54; i<56; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvard + eaExpOffset[i]);
  for(i=56; i<58; ++i)
    eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);
  i=58;
  eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  for(i=59; i<62; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  i=62; /* 2nd of mov */
  eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);
  for(i=63; i<66; ++i) /* scas, cmps */
    eaExp[i] = (void*)((unsigned long)&dlarge + eaExpOffset[i]);
  i=66;
  eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);
  i=67;
  eaExp[i] = (void*)((unsigned long)&dfvard + eaExpOffset[i]);
  i=68;
  eaExp[i] = (void*)((unsigned long)&dfvart + eaExpOffset[i]);
  for(i=69; i<72; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  i=72;
  eaExp[i] = (void*)((unsigned long)&dfvars + eaExpOffset[i]);
  i=73;
  eaExp[i] = (void*)((unsigned long)&dfvard + eaExpOffset[i]);
  i=74;
  eaExp[i] = (void*)((unsigned long)&dfvart + eaExpOffset[i]);
  for(i=75; i<80; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);
  for(i=80; i<82; ++i)
    eaExp[i] = (void*)((unsigned long)&dlarge + eaExpOffset[i]);
  for(i=82; i<85; ++i)
    eaExp[i] = (void*)((unsigned long)&divarw + eaExpOffset[i]);

  /* Duplicate & reduce the stream for cc */

  for(i=0; i<accessExp; ++i) {
    eaExpCC[i] = eaExp[i];
    bcExpCC[i] = bcExp[i];
  }

  reduceCC(ccRed);

  /* Order of reductions matters! It must be right to left. */

  caps = amd_features();
  if(!(caps & CAP_3DNOW))
    reduce(amdRed);
  caps = ia32features();
  if(!(caps & CAP_SSE2))
    reduce(sse2Red);
  if(!(caps & CAP_SSE))
    reduce(sseRed);
  if(!(caps & CAP_MMX))
    reduce(mmxRed);
}
#endif

#ifdef x86_64_unknown_linux2_4

unsigned int loadExp = 73;
unsigned int storeExp = 25;
unsigned int prefeExp = 2;
unsigned int accessExp = 98;
unsigned int accessExpCC = 97;

int eaExpOffset[] =    { 0,0,0,0,0,0,0,                             /* 7 initial stack pushes (EA not checked) */
			 0,0,0,0,0,0,0,0,0,0,0,0,0,                 /* 13 mod=0 loads */
			 4,8,-4,-8,4,8,-4,-8,4,8,-4,-8,127,-128,    /* 14 mod=1 loads */
			 12,0,8,8,8,0,4,8,4,                        /* 9 SIB tests (same as x86) */
			 4,4,4,0,4,0,4,8,0,4,0,0,                   /* 11 semantic tests (one has two accesses) */
			 0,8,0,                                     /* 3 MMX tests */
			 0,0,0,                                     /* 3 SSE tests */
			 0,0,                                       /* 2 SSE2 tests */
			 0,8,0,                                     /* 3 3DNow! tests */
			 0,12,0,0,0,44,25,                          /* 5 REP tests (two have two accesses each) */
			 0,0,0,0,4,8,                               /* x87 */
			 0,0,0,2,4,8,
			 0,0,
			 0,0,
			 0,4,8,                                     /* conditional moves */
			 0,0,0,0,0,0                                /* 6 final stack pops */			 
};

unsigned int bcExp[] = { 8,8,8,8,8,8,8,                  /* 7 initial stack pushes */
			 4,8,4,8,4,8,4,8,4,8,4,8,4,      /* 13 mod=0 loads */
			 4,8,4,8,4,8,4,8,4,8,4,8,4,8,    /* 14 mod=1 loads */
			 4,8,4,8,4,8,4,8,4,              /* 9 SIB tests */
			 4,4,1,1,4,4,4,4,4,4,4,4,        /* 11 semantic tests (one has two accesses) */
			 8,8,8,                          /* 3 MMX tests */                      
			 16,4,0,                         /* 3 SSE tests */
			 16,8,                           /* 2 SSE2 tests */
			 8,8,0,                          /* 3 3DNow! tests */
			 12,16,16,16,49,4,4,             /* 5 REP tests (two have two accesses each) */
			 4,8,10,2,4,8,                   /* x87 */
			 4,8,10,2,4,8,
			 2,2,
                         28,28,
			 4,4,4,                          /* conditional moves */
                         8,8,8,8,8,8                     /* 6 final stack pops */
};

int divarw;
float dfvars;
double dfvard;
long double dfvart;
char dlarge[512] = "keep the interface small and easy to understand.";

extern void* rip_relative_load_address;

void init_test_data()
{
  int i;

  dprintf("&divarw = %p\n", &divarw);
  dprintf("&dfvars = %p\n", &dfvars);
  dprintf("&dfvard = %p\n", &dfvard);
  dprintf("&dfvart = %p\n", &dfvart);
  dprintf("&dlarge = %p\n", &dlarge);

  // we do not check the effective address for stack accesses,
  // since it depends on the stack pointer,
  // so we skip the initial 6 pushes
  i = 7;

  // ModRM and SIB loads and semantic tests (there are 54, but one has two accesses)
  for (; i < 55; i++)
      eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]);
  
  // the 12th is a load from [RIP + 1]
  eaExp[11] = rip_relative_load_address;

  // the 36th access uses RSP
  eaExp[35] = 0;

  // MMX
  assert(i == 55);
  for (; i < 58; i++)
      eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]);

  // SSE
  assert(i == 58);
  for (; i < 60; i++)
      eaExp[i] = (void *)((unsigned long)&dfvart + eaExpOffset[i]);
  assert(i == 60);
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++; // the prefetch

  // SSE2
  assert(i == 61);
  for (; i < 63; i++)
      eaExp[i] = (void *)((unsigned long)&dfvart + eaExpOffset[i]);

  // 3DNow!
  assert(i == 63);
  for (; i < 65; i++)
      eaExp[i] = (void *)((unsigned long)&dfvard + eaExpOffset[i]);
  assert(i == 65);
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;

  // REP prefixes
  assert(i == 66);
  for (; i < 69; i++)
      eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]);
  assert(i == 69);
  eaExp[i] = (void *)((unsigned long)&dfvars + eaExpOffset[i]); i++;
  for (; i < 73; i++)
      eaExp[i] = (void *)((unsigned long)&dlarge + eaExpOffset[i]);

  // x87
  assert(i == 73);
  eaExp[i] = (void *)((unsigned long)&dfvars + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&dfvard + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&dfvart + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;

  eaExp[i] = (void *)((unsigned long)&dfvars + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&dfvard + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&dfvart + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;

  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;
  eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]); i++;

  eaExp[i] = (void *)((unsigned long)&dlarge + eaExpOffset[i]); i++;
   eaExp[i] = (void *)((unsigned long)&dlarge + eaExpOffset[i]); i++;

  // conditional moves
  assert(i == 89);
  for (; i < 92; i++)
      eaExp[i] = (void *)((unsigned long)&divarw + eaExpOffset[i]);

  // duplicate stream for CC (except the second-to-last item)
  for(i = 0; i < 90 ; i++) {
    eaExpCC[i] = eaExp[i];
    bcExpCC[i] = bcExp[i];
  }
  assert(i == 90);
  eaExpCC[i] = eaExp[i+1];
  bcExpCC[i] = bcExp[i+1];
  for(i = 91; i < 97; i++)
      bcExpCC[i] = bcExp[i+1];
  

  
  
}
#endif

#ifdef ia64_unknown_linux2_4

#define loadExp 6
#define storeExp 3
#define prefeExp 3

/* Other platforms don't seem to count prefetches as accesses.  I'm not sure why. */
#define accessExp 12
#define accessExpCC 12

unsigned int bcExp[] = { 8, 8, 8,  8, 8, 8,  8, 16, 16, 0, 0, 0 };
unsigned int bcExpCC[] = { 8, 8, 8,  8, 8, 8,  8, 16, 16, 0, 0, 0 };

/* FIXME: this should be made more complicated and/or assembly
   to actually test all the loads and stores that I know about
   and claim that Dyninst will recognize and handle.  This
   means redefining the stuff above to match up to the new
   code.
   
   FIXME: I don't understand what the "CC" stuff is or does. 
   
   FIXME: I don't understand what the "EA" stuff is or does. 
*/
extern long loadsnstores( long x, long y, long z );

void init_test_data()
{
}
#endif

#ifdef mips_sgi_irix6_4
#define loadExp 0
#define storeExp 0
#define prefeExp 0
#define accessExp 1
#define accessExpCC 1

long loadsnstores(long x, long y, long z)
{
  return x + y + z;
}

unsigned int bcExp[] = { 0 };

void init_test_data()
{
}
#endif

#ifdef alpha_dec_osf4_0
#define loadExp 0
#define storeExp 0
#define prefeExp 0
#define accessExp 1
#define accessExpCC 1

long loadsnstores(long x, long y, long z)
{
  return x + y + z;
}

unsigned int bcExp[] = { 0 };

void init_test_data()
{
}
#endif


/* Sun Forte/WorkShop cc releases older than 6.2 do not like these defines: */
#if !defined(__SUNPRO_C) || (__SUNPRO_C >= 0x530)
#define passorfail(i,p,d,r) if((p)) { \
                              printf("Passed test #%d (%s)\n", (i), (d)); \
                              passedTest[(i)] = TRUE; \
                            } else { \
                              printf("\n**Failed** test #%d (%s): %s\n", (i), (d), (r)); \
                            }

#define skiptest(i,d) { printf("Skipping test #%d (%s)\n", (i), (d)); \
                        printf("    not implemented on this platform\n"); \
                        passedTest[(i)] = TRUE; }
#else
void passorfail(int i, int p, char* d, char* r)
{
  if(p) {
    printf("Passed test #%d (%s)\n", (i), (d));
    passedTest[(i)] = TRUE;
  } else {
    printf("\n**Failed** test #%d (%s): %s\n", (i), (d), (r));
  }
}

void skiptest(int i, char* d)
{
  printf("Skipping test #%d (%s)\n", (i), (d));
  printf("    not implemented on this platform\n");
  passedTest[(i)] = TRUE;
}
#endif

int validateEA(void* ea1[], void* ea2[], unsigned int n)
{
  int ok = 1;
  unsigned int i=0;

  for(; i<n; ++i) {
    ok = (ok && ((ea1[i] == ea2[i]) || ea1[i] == NULL));
    if(!ok) {
      printf("EA Validation failed at access #%d. Expecting: %p. Got: %p.\n", i+1, ea1[i], ea2[i]);
      return 0;
    }
  }
  return 1;
}

int validateBC(unsigned int bc1[], unsigned int bc2[], unsigned int n)
{
  int ok = 1;
  unsigned int i=0;

  for(; i<n; ++i) {
    ok = (ok && (bc1[i] == bc2[i]));
    if(!ok) {
printf("BC Validation failed at access #%d. Expecting: %d. Got: %d.\n", i+1, bc1[i], bc2[i]);
      return 0;
    }
  }
  return 1;
}

void check0()
{
  passorfail(0, result_of_loadsnstores == 9, "function integrity", "function corrupted!");
}

void check1()
{
  passorfail(1, loadCnt == loadExp, "load instrumentation", "load counter seems wrong.");
}

void check2()
{
  passorfail(2, storeCnt == storeExp, "store instrumentation", "store counter seems wrong.");
}

void check3()
{
  passorfail(3, prefeCnt == prefeExp, "prefetch instrumentation", "prefetch counter seems wrong.");
}

void check4()
{
#if !defined(sparc_sun_solaris2_4) \
 &&(!defined(rs6000_ibm_aix4_1) || defined(AIX5)) \
 && !defined(i386_unknown_linux2_0) \
 && !defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */ \
 && !defined(i386_unknown_nt4_0) \
 && !defined(ia64_unknown_linux2_4)
  skiptest(4, "access instrumentation");
#else
  passorfail(4, accessCnt == accessExp, "access instrumentation", "access counter seems wrong.");
  dprintf("accessCnt = %d    accessExp = %d\n", accessCnt, accessExp);
#endif
}

void check5()
{
#if !defined(sparc_sun_solaris2_4) \
 &&(!defined(rs6000_ibm_aix4_1) || defined(AIX5)) \
 && !defined(i386_unknown_linux2_0) \
 && !defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */ \
 && !defined(i386_unknown_nt4_0) \
 && !defined(ia64_unknown_linux2_4)
  skiptest(5, "instrumentation w/ [unconditional] effective address snippet");
#else
  passorfail(5, !doomEA && validateEA(eaExp, eaList, accessExp),
	     "[unconditional] effective address snippet", "address sequences are different");
#endif
}

void check6()
{
#if !defined(sparc_sun_solaris2_4) \
 && !defined(rs6000_ibm_aix4_1) \
 && !defined(i386_unknown_linux2_0) \
 && !defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */ \
 && !defined(i386_unknown_nt4_0) \
 && !defined(ia64_unknown_linux2_4)
  skiptest(6, "instrumentation w/ [unconditional] byte count snippet");
#else
  passorfail(6, !doomBC && validateBC(bcExp, bcList, accessExp),
	     "[unconditional] byte count snippet", "count sequences are different");
#endif
}

void check7()
{
#if !defined(sparc_sun_solaris2_4) \
 &&(!defined(rs6000_ibm_aix4_1) || defined(AIX5)) \
 && !defined(i386_unknown_linux2_0) \
 && !defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */ \
 && !defined(i386_unknown_nt4_0) \
 && !defined(ia64_unknown_linux2_4)
  skiptest(7, "instrumentation w/ conditional effective address snippet");
#else
  passorfail(7, !doomEAcc && validateEA(eaExpCC, eaListCC, accessExpCC),
	     "conditional effective address snippet", "address sequences are different");
#endif
}

void check8()
{
#if !defined(sparc_sun_solaris2_4) \
 && !defined(rs6000_ibm_aix4_1) \
 && !defined(i386_unknown_linux2_0) \
 && !defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */ \
 && !defined(i386_unknown_nt4_0) \
 && !defined(ia64_unknown_linux2_4)
  skiptest(8, "instrumentation w/ conditional byte count snippet");
#else
  passorfail(8, !doomBCcc && validateBC(bcExpCC, bcListCC, accessExpCC),
	     "conditional byte count snippet", "count sequences are different");
#endif
}

/* functions called by the simple instrumentation points */
void countLoad()
{
  ++loadCnt;
}

void countStore()
{
  ++storeCnt;
}

void countPrefetch()
{
  ++prefeCnt;
}

void countAccess()
{
  ++accessCnt;
}


/* functions called by the effective address/byte count instrumentation points */
void listEffAddr(void* addr)
{
  if(accessCntEA < accessExp)
    eaList[accessCntEA] = addr;
  else
    doomEA = 1;
  accessCntEA++;
  dprintf("EA[%d]:%p ", accessCntEA, addr);
}

void listByteCnt(unsigned int count)
{
  if(accessCntBC < accessExp)
    bcList[accessCntBC] = count;
  else
    doomBC = 1;
  accessCntBC++;
  dprintf("BC[%d]:%d ", accessCntBC, count);
}


void listEffAddrCC(void* addr)
{
  if(accessCntEAcc < accessExpCC)
    eaListCC[accessCntEAcc] = addr;
  else
    doomEAcc = 1;
  accessCntEAcc++;
  dprintf("?A[%d]:%p ", accessCntEAcc, addr);
}

void listByteCntCC(unsigned int count)
{
  if(accessCntBCcc < accessExpCC)
    bcListCC[accessCntBCcc] = count;
  else
    doomBCcc = 1;
  accessCntBCcc++;
  dprintf("?C[%d]:%d ", accessCntBCcc, count);
}



int main(int iargc, char *argv[])
{                                       /* despite different conventions */
  unsigned argc=(unsigned)iargc;      /* make argc consistently unsigned */
  unsigned int i, j;
  unsigned int testsFailed = 0;
  
  for (j=0; j <= MAX_TEST; j++) {
    passedTest [j] = FALSE;
    runTest [j] = FALSE;
  }
 
  for (i=1; i < argc; i++) {
    if (!strcmp(argv[i], "-verbose")) {
      debugPrint = TRUE;
    } else if (!strcmp(argv[i], "-runall")) {
      dprintf("selecting all tests\n");
      for (j=1; j <= MAX_TEST; j++) runTest[j] = TRUE;
    } else if (!strcmp(argv[i], "-run")) {
      for (j=i+1; j < argc; j++) {
        unsigned int testId;
        if ((testId = atoi(argv[j]))) {
          if ((testId > 0) && (testId <= MAX_TEST)) {
            dprintf("selecting test %d\n", testId);
            runTest[testId] = TRUE;
          } else {
            printf("invalid test %d requested\n", testId);
            exit(-1);
          }
        } else {
          /* end of test list */
          break;
        }
      }
      i=j-1;
    } else {
      fprintf(stderr, "%s\n", USAGE);
      exit(-1);
    }
  }

  if (argc==1) exit(0);

  loadCnt = 0;
  storeCnt = 0;
  prefeCnt = 0;
  accessCnt = 0;

  result_of_loadsnstores = loadsnstores(2,3,4);
  dprintf("\nresult=0x%x loads=%d stores=%d prefetches=%d accesses=%d\n",
          result_of_loadsnstores, loadCnt, storeCnt, prefeCnt, accessCnt);

  init_test_data();

  /* check0(); integrity check skipped needs more work to be really usefull */
  if (runTest[1]) check1();
  if (runTest[2]) check2();
  if (runTest[3]) check3();
  if (runTest[4]) check4();
  if (runTest[5]) check5();
  if (runTest[6]) check6();
  if (runTest[7]) check7();
  if (runTest[8]) check8();

  /* See how we did running the tests. */
  for (i=1; i <= MAX_TEST; i++) {
    if (runTest[i] && !passedTest[i]) testsFailed++;
  }

  if (!testsFailed) {
    printf("All tests passed\n");
  } else {
    printf("**Failed** %d test%c\n",testsFailed,(testsFailed>1)?'s':' ');
  }

  fflush(stdout);
  dprintf("Mutatee %s terminating.\n", argv[0]);
  return (testsFailed ? 127 : 0);
}
