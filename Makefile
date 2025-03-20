
CC = gcc
#CFLAGS = -g -DDEBUG
CFLAGS = -O -Wall

VERSION = 1.2.2

PAGER = less

FILES = Makefile Onetime.sln Onetime.vcproj README log.txt md5.c \
	md5.h otp.1 otp.c otp.exe random.c test.bat test.mas test.sh

otp:	otp.o md5.o random.o
	$(CC) $(CFLAGS) otp.o md5.o random.o -o otp

manpage:
	nroff -man otp.1 | $(PAGER)

printman:
	groff -man otp.1 | lp

otp.man: otp.1
	nroff -man otp.1 | col -b >otp.man

dist:	clean
	mkdir otp-$(VERSION)
	cp -p $(FILES) otp-$(VERSION)
	tar cfv otp-$(VERSION).tar otp-$(VERSION)
	rm -f otp-$(VERSION).tar.gz
	gzip otp-$(VERSION).tar
	rm -rf otp-$(VERSION)

check:	otp
	chmod u+x test.bat
	./test.sh
	diff test.mas test.out

clean:
	rm -f *.bak *.o otp test.out *.shar core core.* \
	      *.obj *.pdb *.sbr *.bsc *.vcw *.bin t?*.md5 \
	      *.gz *.tar
	rm -rf otp-$(VERSION)
