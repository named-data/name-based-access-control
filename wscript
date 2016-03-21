# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

"""
Copyright (c) 2014-2015,  Regents of the University of California

This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.

ndn-group-encrypt is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
"""

VERSION = "0.0.1"
APPNAME = "libndn-group-encrypt"
BUGREPORT = "http://redmine.named-data.net/projects/gep"
URL = "http://named-data.net/doc/ndn-group-encrypt/"
GIT_TAG_PREFIX = "NDN-GROUP-ENCRYPT"

from waflib import Logs, Utils, Context
import os

def options(opt):
    opt.load(['compiler_c', 'compiler_cxx', 'gnu_dirs'])
    opt.load(['boost', 'default-compiler-flags'],
             tooldir=['.waf-tools'])

    syncopt = opt.add_option_group ("NDN-GROUP-ENCRYPT Options")

    syncopt.add_option('--debug', action='store_true', default=False, dest='debug',
                       help='''debugging mode''')
    syncopt.add_option('--with-tests', action='store_true', default=False, dest='_tests',
                       help='''build unit tests''')

def configure(conf):
    conf.load(['compiler_c', 'compiler_cxx', 'gnu_dirs', 'boost', 'default-compiler-flags'])

    if 'PKG_CONFIG_PATH' not in os.environ:
        os.environ['PKG_CONFIG_PATH'] = Utils.subst_vars('${LIBDIR}/pkgconfig', conf.env)
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    boost_libs = 'system iostreams'
    if conf.options._tests:
        conf.env['NDN_GEP_HAVE_TESTS'] = 1
        conf.define('NDN_GEP_HAVE_TESTS', 1);
        boost_libs += ' unit_test_framework'

    conf.check_boost(lib=boost_libs)

    conf.write_config_header('config.hpp')

def build(bld):
    libndn_group_encrypt = bld(
        target="ndn-group-encrypt",
        # vnum = "0.0.1",
        features=['cxx', 'cxxshlib'],
        source =  bld.path.ant_glob(['src/**/*.cpp']),
        use = 'BOOST NDN_CXX',
        includes = ['src', '.'],
        export_includes=['src', '.'],
        )

    # Unit tests
    if bld.env["NDN_GEP_HAVE_TESTS"]:
        bld.recurse('tests')

    bld.install_files(
        dest = "%s/ndn-group-encrypt" % bld.env['INCLUDEDIR'],
        files = bld.path.ant_glob(['src/**/*.hpp', 'src/**/*.h', 'common.hpp']),
        cwd = bld.path.find_dir("src"),
        relative_trick = True,
        )
        

    bld.install_files(
        dest = "%s/ndn-group-encrypt" % bld.env['INCLUDEDIR'],
        files = bld.path.get_bld().ant_glob(['src/**/*.hpp', 'common.hpp', 'config.hpp']),
        cwd = bld.path.get_bld().find_dir("src"),
        relative_trick = False,
        )

    bld(features = "subst",
        source='ndn-group-encrypt.pc.in',
        target='ndn-group-encrypt.pc',
        install_path = '${LIBDIR}/pkgconfig',
        PREFIX       = bld.env['PREFIX'],
        INCLUDEDIR   = "%s/ndn-group-encrypt" % bld.env['INCLUDEDIR'],
        VERSION      = VERSION,
        )
