# Единая точка сборки/установки для пакетов Arch/Debian/Fedora и `sudo make install`.
#
#   make                      # release-сборка daemon + CLI (eBPF собирается через build.rs)
#   sudo make install         # в /usr/local
#   make install DESTDIR=pkg PREFIX=/usr   # для пакетов

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
DATADIR    ?= $(PREFIX)/share/goodbyedpi
DOCDIR     ?= $(PREFIX)/share/doc/goodbyedpi-ebpf
SYSCONFDIR ?= /etc
UNITDIR    ?= $(PREFIX)/lib/systemd/system

CARGO       ?= cargo
CARGO_FLAGS ?= --release
TARGET_DIR  ?= target/release

.PHONY: all build test install uninstall clean

all: build

build:
	$(CARGO) build $(CARGO_FLAGS) -p goodbyedpi-daemon -p goodbyedpi-cli

test:
	$(CARGO) test --workspace $(CARGO_FLAGS)

install:
	install -Dm0755 $(TARGET_DIR)/goodbyedpi-daemon $(DESTDIR)$(BINDIR)/goodbyedpi-daemon
	install -Dm0755 $(TARGET_DIR)/goodbyedpi $(DESTDIR)$(BINDIR)/goodbyedpi
	install -d $(DESTDIR)$(UNITDIR)
	sed -e 's|/usr/bin/|$(BINDIR)/|g' \
	    -e 's|/usr/share/goodbyedpi|$(DATADIR)|g' \
	    -e 's|/etc/goodbyedpi|$(SYSCONFDIR)/goodbyedpi|g' \
	    systemd/goodbyedpi.service > $(DESTDIR)$(UNITDIR)/goodbyedpi.service
	chmod 0644 $(DESTDIR)$(UNITDIR)/goodbyedpi.service
	install -d $(DESTDIR)$(SYSCONFDIR)/goodbyedpi
	# Пользовательские конфиги не перетираем при повторном `make install`
	for f in goodbyedpi.conf profile.txt; do \
	    [ -e $(DESTDIR)$(SYSCONFDIR)/goodbyedpi/$$f ] || \
	        install -m0644 packaging/etc/$$f $(DESTDIR)$(SYSCONFDIR)/goodbyedpi/$$f; \
	done
	install -d $(DESTDIR)$(DATADIR)/lists $(DESTDIR)$(DATADIR)/bin $(DESTDIR)$(DATADIR)/profiles
	install -m0644 lists/*.txt $(DESTDIR)$(DATADIR)/lists/
	install -m0644 bin/*.bin $(DESTDIR)$(DATADIR)/bin/
	install -m0644 profiles/*.txt $(DESTDIR)$(DATADIR)/profiles/
	install -Dm0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -m0644 docs/*.md $(DESTDIR)$(DOCDIR)/
	install -Dm0644 docs/images/tui-overview.png $(DESTDIR)$(DOCDIR)/images/tui-overview.png

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/goodbyedpi-daemon $(DESTDIR)$(BINDIR)/goodbyedpi
	rm -f $(DESTDIR)$(UNITDIR)/goodbyedpi.service
	rm -rf $(DESTDIR)$(DATADIR) $(DESTDIR)$(DOCDIR)
	@echo "Configs in $(SYSCONFDIR)/goodbyedpi kept"

clean:
	$(CARGO) clean
