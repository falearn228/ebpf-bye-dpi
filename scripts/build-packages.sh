#!/usr/bin/env bash
# Сборка пакетов из текущего рабочего дерева (включая незакоммиченные файлы).
#
#   ./scripts/build-packages.sh deb    # dpkg-buildpackage  -> dist/*.deb
#   ./scripts/build-packages.sh rpm    # rpmbuild           -> dist/*.rpm
#   ./scripts/build-packages.sh arch   # makepkg            -> dist/*.pkg.tar.zst
#   ./scripts/build-packages.sh tarball
#
# Нужен собственный тулчейн дистрибутива (см. packaging/*), Rust >= 1.87.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT_DIR}/dist"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT_DIR}/cli/Cargo.toml" | head -n1)"
# Префикс совпадает с GitHub-архивом тега: ebpf-bye-dpi-<ver>/
PREFIX="ebpf-bye-dpi-${VERSION}"
TARBALL="${DIST}/${PREFIX}.tar.gz"

make_tarball() {
    mkdir -p "${DIST}"
    local list
    list="$(mktemp)"
    # Отслеживаемые + новые неигнорируемые файлы; Cargo.lock игнорируется git'ом, но нужен для --frozen
    (cd "${ROOT_DIR}" && {
        git ls-files --cached --others --exclude-standard
        [[ -f Cargo.lock ]] && echo Cargo.lock
    } | sort -u | while read -r f; do [[ -e "$f" ]] && echo "$f"; done) > "${list}"
    tar -C "${ROOT_DIR}" --transform "s|^|${PREFIX}/|" -czf "${TARBALL}" -T "${list}"
    rm -f "${list}"
    echo "==> ${TARBALL}"
}

build_deb() {
    make_tarball
    local work
    work="$(mktemp -d)"
    tar -C "${work}" -xzf "${TARBALL}"
    cp -r "${ROOT_DIR}/packaging/debian" "${work}/${PREFIX}/debian"
    (cd "${work}/${PREFIX}" && dpkg-buildpackage -us -uc -b)
    mv "${work}"/*.deb "${DIST}/"
    rm -rf "${work}"
    ls -1 "${DIST}"/*.deb
}

build_rpm() {
    make_tarball
    local top="${DIST}/rpmbuild"
    mkdir -p "${top}"/{SOURCES,SPECS}
    cp "${TARBALL}" "${top}/SOURCES/"
    cp "${ROOT_DIR}/packaging/fedora/goodbyedpi-ebpf.spec" "${top}/SPECS/"
    rpmbuild --define "_topdir ${top}" -bb "${top}/SPECS/goodbyedpi-ebpf.spec"
    find "${top}/RPMS" -name '*.rpm' -exec mv {} "${DIST}/" \;
    ls -1 "${DIST}"/*.rpm
}

build_arch() {
    make_tarball
    local work="${DIST}/arch"
    rm -rf "${work}"
    mkdir -p "${work}"
    cp "${ROOT_DIR}/packaging/arch/PKGBUILD" "${work}/"
    # makepkg берёт локальный файл, если он уже лежит рядом под именем из source=()
    cp "${TARBALL}" "${work}/goodbyedpi-ebpf-${VERSION}.tar.gz"
    (cd "${work}" && makepkg -f --noconfirm)
    mv "${work}"/*.pkg.tar.* "${DIST}/"
    ls -1 "${DIST}"/*.pkg.tar.*
}

case "${1:-}" in
    deb) build_deb ;;
    rpm) build_rpm ;;
    arch) build_arch ;;
    tarball) make_tarball ;;
    *)
        echo "Usage: $0 {deb|rpm|arch|tarball}" >&2
        exit 1
        ;;
esac
