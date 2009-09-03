# Makefile to simplify building and cleaning

BINDIR=/usr/local/adm/bin
RCDIR=/usr/local/etc/rc.d
USER=nobody
PROGNAME=seasrvkq
OUTNAME=$(PROGNAME)d
RCSCRIPT=$(PROGNAME).sh

$(OUTNAME): $(PROGNAME).c
	gcc -W -Wall -std=c99 -g -O0 $(PROGNAME).c -o $(OUTNAME)
	sed "s,%%OUTNAME%%,$(OUTNAME),g;s,%%USER%%,$(USER),g;s,%%BINDIR%%,$(BINDIR),g" $(RCSCRIPT).in > $(RCSCRIPT)
	chmod 555 $(RCSCRIPT)
clean:
	rm -rf core $(OUTNAME).core
	rm -rf $(OUTNAME) $(RCSCRIPT)
	rm -rf *~
install: $(OUTNAME)
	install -C $(OUTNAME) $(BINDIR)
	install -C $(RCSCRIPT) $(RCDIR)/$(PROGNAME)
uninstall:
	rm -rf $(RCDIR)/$(PROGNAME)
	rm -rf $(BINDIR)/$(OUTNAME)

