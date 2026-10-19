# Локальная сборка из рабочего дерева: ./scripts/build-packages.sh rpm
%global srcname ebpf-bye-dpi
# Rust-бинарники без отдельного debuginfo-пакета
%global debug_package %{nil}

Name:           goodbyedpi-ebpf
Version:        0.1.0
Release:        1%{?dist}
Summary:        DPI bypass on Linux TC eBPF with a Rust daemon, CLI/TUI and diagnostics

# В репозитории нет LICENSE; eBPF-объект объявляет GPL. Уточнить перед публикацией.
License:        GPL-2.0-only
URL:            https://github.com/falearn228/%{srcname}
Source0:        %{url}/archive/refs/tags/v%{version}/%{srcname}-%{version}.tar.gz

BuildRequires:  cargo >= 1.87
BuildRequires:  rust >= 1.87
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  libbpf-devel
BuildRequires:  elfutils-libelf-devel
BuildRequires:  zlib-devel
BuildRequires:  make
BuildRequires:  systemd-rpm-macros

Requires:       iproute

%description
GoodByeDPI eBPF bypasses DPI using TC egress/ingress eBPF programs and a Rust
userspace daemon that injects split, OOB, fake, TLS record split, disorder and
IP-fragmented packets. The `goodbyedpi` CLI controls the daemon, validates
profiles, hot-reloads them and diagnoses startup failures (`goodbyedpi doctor`).

%prep
%autosetup -n %{srcname}-%{version}

%build
make build

%install
make install DESTDIR=%{buildroot} PREFIX=%{_prefix} UNITDIR=%{_unitdir} \
    SYSCONFDIR=%{_sysconfdir} DOCDIR=%{_docdir}/%{name}

%check
cargo test --workspace --release

%post
%systemd_post goodbyedpi.service

%preun
%systemd_preun goodbyedpi.service

%postun
%systemd_postun_with_restart goodbyedpi.service

%files
%{_bindir}/goodbyedpi
%{_bindir}/goodbyedpi-daemon
%{_unitdir}/goodbyedpi.service
%dir %{_sysconfdir}/goodbyedpi
%config(noreplace) %{_sysconfdir}/goodbyedpi/goodbyedpi.conf
%config(noreplace) %{_sysconfdir}/goodbyedpi/profile.txt
%{_datadir}/goodbyedpi/
%{_docdir}/%{name}/

%changelog
* Mon Oct 19 2026 falearn228 <restsan2003@gmail.com> - 0.1.0-1
- CLI/TUI, doctor, profile validation, dry-run, hot reload, multi-interface
