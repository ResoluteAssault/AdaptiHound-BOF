SUBDIRS := ADHound-BOF IPAHound-BOF
.PHONY: all bof $(SUBDIRS) ad freeipa clean
all: $(SUBDIRS)
bof: all
ad: ADHound-BOF
freeipa: IPAHound-BOF
$(SUBDIRS):
	$(MAKE) --no-print-directory -C $@
clean:
	$(MAKE) --no-print-directory -C ADHound-BOF clean
	$(MAKE) --no-print-directory -C IPAHound-BOF clean
