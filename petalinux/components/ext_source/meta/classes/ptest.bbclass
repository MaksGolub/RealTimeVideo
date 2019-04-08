SUMMARY_${PN}-ptest ?= "${SUMMARY} - Package test files"
DESCRIPTION_${PN}-ptest ?= "${DESCRIPTION}  \
This package contains a test directory ${PTEST_PATH} for package test purposes."

PTEST_PATH ?= "${libdir}/${BPN}/ptest"
PTEST_BUILD_HOST_FILES ?= "Makefile"
PTEST_BUILD_HOST_PATTERN ?= ""

FILES_${PN}-ptest = "${PTEST_PATH}"
SECTION_${PN}-ptest = "devel"
ALLOW_EMPTY_${PN}-ptest = "1"
PTEST_ENABLED = "${@bb.utils.contains('DISTRO_FEATURES', 'ptest', '1', '0', d)}"
PTEST_ENABLED_class-native = ""
PTEST_ENABLED_class-nativesdk = ""
PTEST_ENABLED_class-cross-canadian = ""
RDEPENDS_${PN}-ptest_class-native = ""
RDEPENDS_${PN}-ptest_class-nativesdk = ""
RRECOMMENDS_${PN}-ptest += "ptest-runner"

PACKAGES =+ "${@bb.utils.contains('PTEST_ENABLED', '1', '${PN}-ptest', '', d)}"

do_configure_ptest() {
    :
}

do_configure_ptest_base() {
    do_configure_ptest
}

do_compile_ptest() {
    :
}

do_compile_ptest_base() {
    do_compile_ptest
}

do_install_ptest() {
    :
}

do_install_ptest_base() {
    if [ -f ${WORKDIR}/run-ptest ]; then
        install -D ${WORKDIR}/run-ptest ${D}${PTEST_PATH}/run-ptest
    fi
    if grep -q install-ptest: Makefile; then
        oe_runmake DESTDIR=${D}${PTEST_PATH} install-ptest
    fi
    do_install_ptest
    chown -R root:root ${D}${PTEST_PATH}

    # Strip build host paths from any installed Makefile
    for filename in ${PTEST_BUILD_HOST_FILES}; do
        for installed_ptest_file in $(find ${D}${PTEST_PATH} -type f -name $filename); do
            bbnote "Stripping host paths from: $installed_ptest_file"
            sed -e 's#${HOSTTOOLS_DIR}/*##g' \
                -e 's#${WORKDIR}/*=#.=#g' \
                -e 's#${WORKDIR}/*##g' \
                -i $installed_ptest_file
            if [ -n "${PTEST_BUILD_HOST_PATTERN}" ]; then
               sed -E '/${PTEST_BUILD_HOST_PATTERN}/d' \
                   -i $installed_ptest_file
            fi
        done
    done
}

do_configure_ptest_base[dirs] = "${B}"
do_compile_ptest_base[dirs] = "${B}"
do_install_ptest_base[dirs] = "${B}"
do_install_ptest_base[cleandirs] = "${D}${PTEST_PATH}"

addtask configure_ptest_base after do_configure before do_compile
addtask compile_ptest_base   after do_compile   before do_install
addtask install_ptest_base   after do_install   before do_package do_populate_sysroot

python () {
    if not bb.data.inherits_class('native', d) and not bb.data.inherits_class('cross', d):
        d.setVarFlag('do_install_ptest_base', 'fakeroot', '1')
        d.setVarFlag('do_install_ptest_base', 'umask', '022')

    # Remove all '*ptest_base' tasks when ptest is not enabled
    if not(d.getVar('PTEST_ENABLED') == "1"):
        for i in ['do_configure_ptest_base', 'do_compile_ptest_base', 'do_install_ptest_base']:
            bb.build.deltask(i, d)
}
