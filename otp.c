/*

			One-Time Pad Generator

	            	    by John Walker
		       http://www.fourmilab.ch/

    Creates ready to use one-time pads containing either passwords
    that obey the digraph frequencies of English text (less secure
    but easier to remember), completely random letters, or digits.

    Random values for the pad are generated from the XOR of four
    concurrently-running BSD random() generators, each with a 256 byte
    state vector, independently seeded with four 4 byte blocks of the
    MD5 message digest of a vector containing:
    
	Time and date (time())
	Several hundred bytes of unitialised storage

    and, depending on the operating system:

	MSDOS:
	    Default drive size and free space
	    Absolute address program loaded in memory

	Unix:
            Time in microseconds (to system's timer resolution)
	    Process ID number
	    Parent process ID number
            Machine's host ID

    The English-digraph password generator is based on the "mpw"
    program developed at MIT:

    mpw:  Make up passwords which have similar letter digraph
	  frequencies to English.
    Converted from Multics PL/I by Bill Sommerfeld, 4/21/86.
    Original PL/I version provided by Jerry Saltzer.

		This program is in the public domain.
*/

#define VERSION "1.2.2, June 2014"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef MSDOS
#include <dos.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif

#ifdef __APPLE__
#include <sys/time.h>
extern int getpid(), getppid(), gethostid();
#endif

#include "md5.h"

#define V   (void)

/*  Globals imported.  Depending on your system you may want/need to
    replace these with includes of the proper header files.  */

extern int32_t o_random();
extern char *o_initstate();
extern char *o_setstate();

#define PW_LENGTH 8		      /* Default password length */

/* Frequency of English digraphs (from D Edwards 1/27/66) */

static int frequency[26][26] = {
    {4, 20, 28, 52, 2, 11, 28, 4, 32, 4, 6, 62, 23, 167, 2, 14, 0, 83, 76, 127, 7, 25, 8, 1, 9, 1}, /* aa - az */
    {13, 0, 0, 0, 55, 0, 0, 0, 8, 2, 0, 22, 0, 0, 11, 0, 0, 15, 4, 2, 13, 0, 0, 0, 15, 0}, /* ba - bz */
    {32, 0, 7, 1, 69, 0, 0, 33, 17, 0, 10, 9, 1, 0, 50, 3, 0, 10, 0, 28, 11, 0, 0, 0, 3, 0}, /* ca - cz */
    {40, 16, 9, 5, 65, 18, 3, 9, 56, 0, 1, 4, 15, 6, 16, 4, 0, 21, 18, 53, 19, 5, 15, 0, 3, 0}, /* da - dz */
    {84, 20, 55, 125, 51, 40, 19, 16, 50, 1, 4, 55, 54, 146, 35, 37, 6, 191, 149, 65, 9, 26, 21, 12, 5, 0}, /* ea - ez */
    {19, 3, 5, 1, 19, 21, 1, 3, 30, 2, 0, 11, 1, 0, 51, 0, 0, 26, 8, 47, 6, 3, 3, 0, 2, 0}, /* fa - fz */
    {20, 4, 3, 2, 35, 1, 3, 15, 18, 0, 0, 5, 1, 4, 21, 1, 1, 20, 9, 21, 9, 0, 5, 0, 1, 0}, /* ga - gz */
    {101, 1, 3, 0, 270, 5, 1, 6, 57, 0, 0, 0, 3, 2, 44, 1, 0, 3, 10, 18, 6, 0, 5, 0, 3, 0}, /* ha - hz */
    {40, 7, 51, 23, 25, 9, 11, 3, 0, 0, 2, 38, 25, 202, 56, 12, 1, 46, 79, 117, 1, 22, 0, 4, 0, 3}, /* ia - iz */
    {3, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0}, /* ja - jz */
    {1, 0, 0, 0, 11, 0, 0, 0, 13, 0, 0, 0, 0, 2, 0, 0, 0, 0, 6, 2, 1, 0, 2, 0, 1, 0}, /* ka - kz */
    {44, 2, 5, 12, 62, 7, 5, 2, 42, 1, 1, 53, 2, 2, 25, 1, 1, 2, 16, 23, 9, 0, 1, 0, 33, 0}, /* la - lz */
    {52, 14, 1, 0, 64, 0, 0, 3, 37, 0, 0, 0, 7, 1, 17, 18, 1, 2, 12, 3, 8, 0, 1, 0, 2, 0}, /* ma - mz */
    {42, 10, 47, 122, 63, 19, 106, 12, 30, 1, 6, 6, 9, 7, 54, 7, 1, 7, 44, 124, 6, 1, 15, 0, 12, 0}, /* na - nz */
    {7, 12, 14, 17, 5, 95, 3, 5, 14, 0, 0, 19, 41, 134, 13, 23, 0, 91, 23, 42, 55, 16, 28, 0, 4, 1}, /* oa - oz */
    {19, 1, 0, 0, 37, 0, 0, 4, 8, 0, 0, 15, 1, 0, 27, 9, 0, 33, 14, 7, 6, 0, 0, 0, 0, 0}, /* pa - pz */
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0}, /* qa - qz */
    {83, 8, 16, 23, 169, 4, 8, 8, 77, 1, 10, 5, 26, 16, 60, 4, 0, 24, 37, 55, 6, 11, 4, 0, 28, 0}, /* ra - rz */
    {65, 9, 17, 9, 73, 13, 1, 47, 75, 3, 0, 7, 11, 12, 56, 17, 6, 9, 48, 116, 35, 1, 28, 0, 4, 0}, /* sa - sz */
    {57, 22, 3, 1, 76, 5, 2, 330, 126, 1, 0, 14, 10, 6, 79, 7, 0, 49, 50, 56, 21, 2, 27, 0, 24, 0}, /* ta - tz */
    {11, 5, 9, 6, 9, 1, 6, 0, 9, 0, 1, 19, 5, 31, 1, 15, 0, 47, 39, 31, 0, 3, 0, 0, 0, 0}, /* ua - uz */
    {7, 0, 0, 0, 72, 0, 0, 0, 28, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0}, /* va - vz */
    {36, 1, 1, 0, 38, 0, 0, 33, 36, 0, 0, 4, 1, 8, 15, 0, 0, 0, 4, 2, 0, 0, 1, 0, 0, 0}, /* wa - wz */
    {1, 0, 2, 0, 0, 1, 0, 0, 3, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 3, 0, 0, 1, 0, 0, 0}, /* xa - xz */
    {14, 5, 4, 2, 7, 12, 12, 6, 10, 0, 0, 3, 7, 5, 17, 3, 0, 4, 16, 30, 0, 0, 5, 0, 0, 0}, /* ya - yz */
    {1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}   /* za - zz */
};

/* This MUST be equal to the sum of the equivalent rows above. */

static int row_sums[26] = {
    796,   160,    284,    401,    1276,   262,    199,    539,    777,    
    16,    39,	   351,    243,    751,    662,    181,    17,	   683,    
    662,   968,    248,    115,    180,    17,	   162,    5
};

/* Frequencies of starting characters. */

static int start_freq [26] = {
    1299,  425,    725,    271,    375,    470,    93,	   223,    1009,
    24,    20,	   355,    379,    319,    823,    618,    21,	   317,
    962,   1991,   271,    104,    516,    6,	   16,	   14
};

/* This MUST be equal to the sum of all elements in the above array. */

static int total_sum = 11646;

/* Random number generator state vectors. */

#define RandVecL 256
typedef char randvec[RandVecL];
static randvec rvec[4];

/*  USAGE  --  Print how-to-call information.  */

static void usage(void)
{
    V fprintf(stderr, "otp  --  One-time pad generator.\n");
    V fprintf(stderr, "\n");
    V fprintf(stderr, "Usage: otp [options] [output_file]\n");
    V fprintf(stderr, "Defaults   Options\n");
    V fprintf(stderr, "           -Cn        Capital letter keys of n characters\n");
    V fprintf(stderr, "           -Dn        Numeric digit keys of n characters\n");
    V fprintf(stderr, "           -En        English word-like keys of n characters\n");
    V fprintf(stderr, "    8      -Ln        Lower case letter keys of n characters\n");
    V fprintf(stderr, "           -Msigfile  Write MD5 signatures of keys in sigfile\n");
    V fprintf(stderr, "   50      -Nn        Generate n keys\n");
    V fprintf(stderr, "           -Rseed     Set seed for random number generator\n");
    V fprintf(stderr, "    4      -Sn        Separator every n characters\n");
    V fprintf(stderr, "           -U         Print this message\n");
    V fprintf(stderr, "   80      -Wn        Output lines <= n characters\n");
    V fprintf(stderr, "\n");
    V fprintf(stderr, "Version " VERSION "\n");
    V fprintf(stderr, "by John Walker\n");
    V fprintf(stderr, "   http://www.fourmilab.ch/\n");
}

/*  MRANDOM  --  Combine the results of four independently-seeded
		 concurrently running random number generators to
		 produce a random value based on a 16 byte seed.  */

static long mrandom(void)
{
    int i;
    int32_t r = 0;

    for (i = 0; i < 4; i++) {
	o_setstate(rvec[i]);
	r ^= o_random();
    }
    return r;
}

/*  Main program.  */

int main(int argc, char *argv[])
{
    int i, j, row_position, nchars, position,
	line, lbase, npass = 50, ndig, sep = 4,
	numeric = 0, upper = 0, english = 0,
	pw_length = PW_LENGTH, pw_item, linelen = 79,
	npline, lineno, nch;
    int32_t rseed;
    char *password, *pwp, *v, *seed = NULL;
    FILE *ofile = stdout, *sigfile = NULL;
    uint32_t trash[100];
    struct MD5Context md5c;
    unsigned char digest[16];
#ifdef MSDOS
    union _REGS ri, ro;
#endif	
#ifdef __APPLE__
    struct timeval tv;
#endif
    
    for (i = 1; i < argc; i++) {
	char *op, opt;

	op = argv[i];
        if (*op == '-') {
	    opt = *(++op);
	    if (islower(opt)) {
		opt = toupper(opt);
	    }

	    switch (opt) {
                case 'C':
		    numeric = 0;
		    upper = 1;
scanl:		    if ((j = atoi(op + 1)) > 0) {
			pw_length = j;
		    }
		    break;

                case 'D':             /* -Dlen  Numeric digit keys */
		    numeric = 1;
		    goto scanl;

                case 'E':             /* -Elen  English word like keys */
		    english = 1;
		    goto scanl;

                case 'L':             /* -Llen  Lower case letter keys */
		    numeric = 0;
		    upper = 0;
		    goto scanl;

                case 'M':             /* -Msigfile  Write MD5 signatures of keys in sigfile */
                    if ((sigfile = fopen(op + 1, "w")) == NULL) {
                        fprintf(stderr, "Cannot create MD5 signature file %s\n", op + 1);
			return 2;
		    }
		    break;

                case 'N':             /* -Ncount  Generate count keys */
		    npass = atoi(op + 1);
		    if (npass < 1) {
			npass = 50;
		    }
		    break;
		    
                case 'R':             /* -Rstring  Specify seed for random generator */
		    seed = op + 1;
		    break;

                case 'S':             /* -Schars  Insert a separator every chars */
		    sep = atoi(op + 1);
		    break;

                case 'U':             /* -U  Print how to call information */
                case '?':
		    usage();
		    return 0;

                case 'W':             /* -Wn  Break lines for a width of n characters */
		    linelen = atoi(op + 1);
		    break;
	    }
	} else {
	    if (ofile != stdout) {
                fprintf(stderr, "Error: duplicate output file specification.\n");
		usage();
		return 2;
	    }
            ofile = fopen(op, "w");
	    if (ofile == NULL) {
                fprintf(stderr, "Cannot create output file %s\n", op);
		return 2;
	    }
	}
    }

    lbase = upper ? 'A' : 'a';
    ndig = 1;
    j = 10;
    while (npass >= j) {
	ndig++;
	j *= 10;
    }

    pw_item = pw_length + (sep > 0 ? (pw_length / sep) : 0);
    password = (char *) malloc(pw_item + 1);
    pw_item += ndig + 5;
    j = pw_item * 3;
    if (j < 132) {
	j = 132;
    }
    v = (char *) malloc(j);
    if (password == NULL || v == NULL) {
        fprintf(stderr, "Cannot allocate password buffers.\n");
	return 2;
    }
    npline = linelen / pw_item;
    if (npline < 1) {
	npline = 0;
    }
    
    MD5Init(&md5c);
    if (seed != NULL) {
#ifdef DEBUG
        fprintf(stderr, "Seed string: \"%s\"\n", seed);
#endif
	MD5Update(&md5c, (unsigned char *) seed, strlen(seed));
    } else {

	/* Seed the random generator from the time of day
	   and a variety of system environment information
	   unlikely to be easily guessed. */
#ifdef MSDOS
	ri.h.ah = 0x36; 	/* Get disc free space */
	ri.h.dl = 0;		/* Default drive */
	if (_intdos(&ri, &ro) != 0xFFFF) {
	    trash[1] = (((int32_t) ro.x.ax) << 16) | ro.x.bx;
	    trash[2] = (((int32_t) ro.x.cx) << 16) | ro.x.dx; 
	}
	trash[4] = (int32_t) (char __far *) trash; 
#define OS_KNOWN 1
#endif

#ifdef WIN32
     MEMORYSTATUS ms;
     POINT p;

     /*	The following gets all kind of information likely
    	to vary from moment to moment and uses it as the initial
    	seed for the random number generator.  If any of these
    	causes porting problems in the future, just delete them.  */

     trash[1] = GetTickCount();
     trash[2] = (unsigned long) (((HWND) NULL) - GetActiveWindow());
     trash[3] = GetFreeSpace(0);
     ms.dwLength = sizeof(MEMORYSTATUS);
     GlobalMemoryStatus(&ms);
     trash[4] = ms.dwMemoryLoad; 
     trash[5] = (unsigned long) ms.dwAvailPhys; 
     trash[6] = (unsigned long) ms.dwAvailPageFile; 
     GetCursorPos(&p);
     trash[7] = p.x;
     trash[8] = p.y; 
#define OS_KNOWN 1
#endif

#ifdef __APPLE__
    FILE *rf;
    size_t ct;
    
	gettimeofday(&tv, (struct timezone *) NULL);
	trash[1] = tv.tv_sec;
	trash[2] = tv.tv_usec;
        /* If any of these don't exist on your system, just
	   delete the call and/or replace it with something
	   else in the environment. */
	trash[4] = getpid();
	trash[11] = getppid();
	trash[38] = gethostid();
	/* If the system implements /dev/random, obtain 16 bytes
	   of entropy thence. */
	if ((rf = fopen("/dev/random", "r")) != NULL) {
	    ct = fread(&(trash[60]), 1, 16, rf);
            if (ct == 0) {
                fprintf(stderr, "No data read from /dev/random.\n");
            }
	    fclose(rf);
	}
#define OS_KNOWN 1
#endif

#ifndef OS_KNOWN
        fprintf(stderr, "No operating system sensed in otp.c compile.\n");
	exit(2);
#endif

	trash[0] = (unsigned long) time(NULL);
	
	MD5Update(&md5c, (unsigned char *) trash, sizeof trash);
    }	 
    MD5Final(digest, &md5c);
    for (j = 0; j < 4; j++) {
	rseed = (((int32_t) digest[0 + (4 * j)]) << 24) |
		 (((int32_t) digest[1 + (4 * j)]) << 16) |
		 (((int32_t) digest[2 + (4 * j)]) << 8) | digest[3 + (4 * j)];
	o_initstate(rseed, rvec[j], RandVecL);
#ifdef DEBUG
        fprintf(stderr, "Digest[%d : %d]:", j * 4, (j * 4) + 3);
	for (i = 0; i < 4; i++) {
            fprintf(stderr, " %02X", digest[i + (4 * j)]);
	}
        fprintf(stderr, "\n");
        fprintf(stderr, "Seed[%d]: %08lX\n", j, rseed);
#endif
    }

    /* "Cook" the random number generator for a random number
       of cycles to gnarl things up some more. */

    for (i = 0; i < (28 + digest[8]); i++) {
	(void) mrandom();
    }

#ifdef RTEST
    {
	char rt[1024];
        FILE *fo = fopen("rtest.bin",
#ifdef MSDOS
                                      "wb"
#else
                                      "w"
#endif
			);

	for (i = 0; i < 64; i++) {
	    for (j = 0; j < 1024; j++) {
		rt[j] = mrandom() >> 7;
	    }
	    fwrite(rt, sizeof rt, 1, fo);
	}
	fclose(fo);
	exit(0);
    }
#endif

    v[0] = 0;
    lineno = 0;
    for (line = 1; line <= npass; line++) {
	if (numeric) {
	    pwp = password;
	    for (nchars = 0; nchars < pw_length; nchars++) {
		if ((sep > 0) && ((nchars % sep) == 0) && (nchars > 0)) {
                    *pwp++ = '-';
		}
                *pwp++ = '0' + (int) ((mrandom() >> 7) % 10);
	    }
	} else if (!english) {
	    pwp = password;
	    for (nchars = 0; nchars < pw_length; nchars++) {
		if ((sep > 0) && ((nchars % sep) == 0) && (nchars > 0)) {
                    *pwp++ = '-';
		}
		*pwp++ = lbase + (int) ((mrandom() >> 7) % 26);
	    }
	} else {
	    position = (int) (mrandom() % total_sum);
	    for (row_position = 0, j = 0; position >= row_position;
		 row_position += start_freq[j], j++)
		continue;
	    *(pwp = password) = j + lbase - 1;
	    nch = 1;
	    for (nchars = pw_length - 1; nchars; --nchars) {
		i = *pwp - lbase;
		pwp++;

		/* Now find random position within the row. */

		position = (int) (mrandom() % row_sums[i]);
		for (row_position = 0, j = 0;
		     position >= row_position;
		     row_position += frequency[i][j], j++)
		    continue;

		if ((sep > 0) && ((nch % sep) == 0)) {
                    *pwp++ = '-';
		}
		nch++;
		*pwp = j + lbase - 1;
	    }
	    pwp++;
	}
        *pwp = '\0';

	/* Output the generated password, and the line if it is full. */

        sprintf(v + strlen(v), "%*d) %s  ", ndig, line, password);
	if ((++lineno) >= npline) {
            fprintf(ofile, "%s\n", v);
	    v[0] = 0;
	    lineno = 0;
	}

	/* If a signature file is being written, compute the MD5 signature
	   of this item and append it to the signature file. */

	if (sigfile != NULL) {
	    int k;

	    MD5Init(&md5c);
	    MD5Update(&md5c, (unsigned char *) password, strlen(password));
	    MD5Final(digest, &md5c);
	    for (k = 0; k < 16; k++) {
                fprintf(sigfile, "%02X", digest[k]);
	    }
            fprintf(sigfile, "\n");
	}
    }
    if (strlen(v) > 0) {
        fprintf(ofile, "%s\n", v);
    }
    fclose(ofile);
    return 0;
}
