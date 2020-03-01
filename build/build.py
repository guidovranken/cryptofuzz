#!/usr/bin/env python3

# Cryptofuzz build system

import os, subprocess, tempfile, shutil

def exec(full_args, cwd=None):
    if subprocess.call(full_args, cwd=cwd) != 0:
        raise RuntimeError('subprocess failed: ' + str(full_args))

def create_temp_path():
    return Path(tempfile.mkdtemp())

def get_subdirectory(path):
    subdirs = [subdir for subdir in os.listdir(path) if os.path.isdir(os.path.join(path, subdir))]
    if len(subdirs) != 1:
        raise RuntimeError('more than 1 subdirectory found')
    return os.path.join(path, subdirs[0])

class BuildArguments(object):
    def __init(self, include_paths, objects):
        self.include_paths = include_paths
        self.objects = objects

class Path(object):
    def __init__(self, path):
        assert(len(path) >= 2 and path[0] == '/')
        self.path = path
    def __del__(self):
        shutil.rmtree(self.path)
    def get(self):
        return self.path

def unpack(archive):
    path = create_temp_path()

    if archive.endswith('.tar.gz'):
        sysexec(['tar', 'zxf', archive, '--directory', path.get()])
    elif archive.endswith('.zip'):
        sysexec(['unzip', archive, '-d', path.get()])
    else:
        raise RuntimeError('unsupported archive extension')

    return path

class Command(object):
    def __init__(self, path, command, arguments=[]):
        self.path = path
        self.command = command
        self.arguments = arguments
    def run(self):
        full_args = []
        full_args.extend([self.command])
        full_args.extend(self.arguments)
        sysexec(full_args, self.path)

class MakeCommand(Command):
    def __init__(self, path, arguments=[]):
        super().__init__(path, 'make', ['-j6']) # TODO actual number of processors
        self.arguments.extend(arguments)

class AutoreconfCommand(Command):
    def __init__(self, path, arguments=[]):
        super().__init__(path, 'autoreconf', ['if'])

class Builder(object):
    def __init__(self, arguments, module_define, module_path):
        self.arguments = arguments
        self.module_define = module_define
        self.module_path = module_path
    def build_library(self):
        raise NotImplementedError
    def get_module_build_arguments(self):
        raise NotImplementedError
    def build(self):
        build_library()
        build_cryptofuzz_module()
    def build_cryptofuzz_module(self):
        assert(self.module_path)
        assert(self.module_define)

        build = MakeCommand(
                            path=arguments['cryptofuzz_path'] + '/modules/' + self.module_path,
                            arguments=[
                                        '-B',
                                        '-DCRYPTOFUZZ_' + self.module_define])
        build.run()

class OpenSSLBased(Builder):
    def __init__(self, arguments):
        super().__init__(arguments, 'OPENSSL', 'openssl')
    def build_library(self):
        pass

class OpenSSL(OpenSSLBased):
    def __init__(self, arguments):
        super().__init__(arguments)
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[self.source_path + '/include'],
                objects=[self.source_path + '/libcrypto.a'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())

        config_arguments = ['enable-rc2', 'enable-rc5']

        if self.arguments['with_asm'] == False:
            config_arguments += ['no-asm']

        config = Command(
                path=self.source_path,
                command='./config',
                arguments=config_arguments)
        config.run()

        build = MakeCommand(path=self.source_path)
        build.run()

class LibreSSL(OpenSSLBased):
    def __init__(self, arguments):
        super().__init__(arguments)
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[self.source_path + '/include'],
                objects=[self.build_path.get() + '/crypto/libcrypto.a'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())
        self.build_path = create_temp_path()

        config_arguments = [
                '-DCMAKE_C_COMPILER="{}"'.format( self.arguments['cc'] ),
                '-DCMAKE_CXX_COMPILER="{}"'.format( self.arguments['cxx'] ),
                '-DCMAKE_CXX_FLAGS="{}"'.format( self.arguments['cxxflags'] ),
                '-DCMAKE_C_FLAGS="{}"'.format( self.arguments['cflags'] ),
                self.source_path]

        if self.arguments['with_asm'] == False:
            config_arguments += ['-DENABLE_ASM=OFF']

        config = Command(
                path=build_path.get(),
                command='cmake',
                arguments=config_arguments)
        config.run()

        build = MakeCommand(path=self.build_path.get())
        build.run()

class BoringSSL(OpenSSLBased):
    def __init__(self, arguments):
        super().__init__(arguments)
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[self.source_path + '/include'],
                objects=[self.build_path.get() + '/crypto/libcrypto.a'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())
        self.build_path = create_temp_path()

        config_arguments = [
                '-DCMAKE_CXX_FLAGS="{}"'.format( self.arguments['cxxflags'] ),
                '-DCMAKE_C_FLAGS="{}"'.format( self.arguments['cflags'] ),
                '-DBORINGSSL_ALLOW_CXX_RUNTIME=1',
                self.source_path]

        if self.arguments['with_asm'] == False:
            config_arguments += ['-DOPENSSL_NO_ASM=1']

        config = Command(
                path=self.build_path.get(),
                command='cmake',
                arguments=config_arguments)
        config.run()

        build = MakeCommand(
                            path=self.build_path.get(),
                            arguments=['crypto'])
        build.run()

class Botan(Builder):
    def __init__(self, arguments):
        super().__init__(arguments, 'BOTAN', 'botan')

        if arguments['architecture'] == 'x64':
            self.config_cpu_argument = 'x64'
        elif self.config_cpu_argument == 'x86':
            self.config_cpu_argument = 'x86_32'
        else:
            raise RuntimeError('unsupported architecture')
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[self.source_path + '/build/include'],
                objects=[self.source_path + '/libbotan-2.a'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())

        config_arguments = [
                            '--cpu=' + self.config_cpu_argument,
                            '--cc-bin={}'.format( self.arguments['cxx'] ),
                            '--cc-abi-flags="{}"'.format( self.arguments['cxxflags'] ),
                            '--disable-shared',
                            '--disable-modules=locking_allocator']
        config = Command(
                path=self.source_path,
                command='./configure.py',
                arguments=config_arguments)
        config.run()

        build = MakeCommand(path=self.source_path)
        build.run()

class WolfCrypt(Builder):
    def __init__(self, arguments):
        super().__init__(arguments, 'WOLFCRYPT', 'wolfcrypt')
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[self.source_path],
                objects=[self.source_path + '/src/.libs/libwolfssl.a'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())

        #autoreconf = AutoreconfCommand(path=self.source_path)
        #autoreconf.run();

        autogen = Command(path=self.source_path, command='./autogen.sh')
        autogen.run()

        config_arguments = [
                            '--enable-static'
                            '--enable-md2'
                            '--enable-md4'
                            '--enable-ripemd'
                            '--enable-blake2'
                            '--enable-blake2s'
                            '--enable-pwdbased'
                            '--enable-scrypt'
                            '--enable-hkdf'
                            '--enable-cmac'
                            '--enable-arc4'
                            '--enable-camellia'
                            '--enable-rabbit'
                            '--enable-aesccm'
                            '--enable-aesctr'
                            '--enable-hc128'
                            '--enable-xts'
                            '--enable-des3'
                            '--enable-idea'
                            '--enable-x963kdf'
                            '--enable-harden']

        if self.arguments['with_asm'] == False:
            config_arguments += ['--disable-asm']
        if self.arguments['architecture'] == 'x86':
            config_arguments += ['--disable-fastmath']

        config = Command(
                path=self.source_path,
                command='./configure',
                arguments=config_arguments)
        config.run()

        build = MakeCommand(path=self.source_path)
        build.run()

class MbedTLS(Builder):
    def __init__(self, arguments):
        super().__init__(arguments, 'MBEDTLS', 'mbedtls')
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[self.source_path],
                objects=[self.build_path.get() + '/library/libmbedcrypto.a'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())
        self.build_path = create_temp_path()

        config_setters = [
                            Command(
                                    path=self.source_path,
                                    command='scripts/config.pl',
                                    arguments = ['set', 'MBEDTLS_PLATFORM_MEMORY'])]
        if self.arguments['with_asm'] == False:
            config_setters += [
                                Command(
                                    path=self.source_path,
                                    command='scripts/config.pl',
                                    arguments = ['unset', 'MBEDTLS_HAVE_ASM']),
                                Command(
                                    path=self.source_path,
                                    command='scripts/config.pl',
                                    arguments = ['unset', 'MBEDTLS_PADLOCK_C']),
                                Command(
                                    path=self.source_path,
                                    command='scripts/config.pl',
                                    arguments = ['unset', 'MBEDTLS_AESNI_C'])],
        [C.run() for C in config_setters]

        config_arguments = [
                            '-DENABLE_PROGRAMS=0',
                            '-DENABLE_TESTING=0',
                            self.source_path]

        config = Command(
                path=self.build_path.get(),
                command='cmake',
                arguments=config_arguments)
        config.run()

        build = MakeCommand(path=self.build_path.get())
        build.run()

class CryptoPP(Builder):
    def __init__(self, arguments):
        super().__init__(arguments, 'CRYPTOPP', 'cryptopp')
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[self.source_path],
                objects=[self.source_path.get() + '/libcryptopp.a'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())

        build = MakeCommand(path=self.source_path)
        build.run()

class EverCrypt(Builder):
    def __init__(self, arguments):
        super().__init__(arguments, 'EVERCRYPT', 'evercrypt')
    def get_module_build_arguments(self):
        return BuildArguments(
                include_paths=[
                                self.source_path + '/dist',
                                self.source_path + '/dist/kremlin/include'],
                objects=[
                            self.build_path.get() + '/dist/portable/libevercrypt.a',
                            self.build_path.get() + '/dist/kremlin/kremlib/dist/minimal/*.o'])
    def build_library(self):
        source_base_path = unpack(self.arguments['source_archive_path'])
        self.source_path = get_subdirectory(source_base_path.get())

        build1 = MakeCommand(
                            path=self.source_path + '/dist',
                            arguments=[
                                        '-C',
                                        'portable',
                                        'libevercrypt.a'])
        build1.run()

        build2 = MakeCommand(
                            path=self.source_path + '/dist',
                            arguments=[
                                        '-C',
                                        'kremlin/kremlib/dist/minimal',
                                        'libevercrypt.a'])
        build2.run()

repository = {
                'openssl', OpenSSL,
                'libressl', LibreSSL,
                'boringssl', BoringSSL,
                'botan', Botan,
                'wolfcrypt', WolfCrypt,
                'mbedtls', MbedTLS,
                'cryptopp', CryptoPP,
                'evercrypt', EverCrypt}

# OK
#b = CryptoPP(arguments = {'source_archive_path' : 'CRYPTOPP_8_2_0.tar.gz'})
#b.build_library()

# OK
#b = OpenSSL(arguments = {'source_archive_path' : 'openssl-master.zip', 'with_asm' : True})
#b.build_library()

# OK
#b = MbedTLS(arguments = {'source_archive_path' : 'mbedcrypto-3.1.0.tar.gz', 'with_asm' : True})
#b.build_library()

# OK
#b = WolfCrypt(arguments = {'source_archive_path' : 'v4.3.0-stable.tar.gz', 'with_asm' : True, 'architecture' : 'x64'})
#b.build_library()

# OK
#b = BoringSSL(arguments = {'source_archive_path' : 'boringssl-master.zip', 'with_asm' : True, 'cflags' : '', 'cxxflags' : ''})
#b.build_library()

# TODO requires multiple source packages
#b = LibreSSL(arguments = {'source_archive_path' : '', 'with_asm' : True, 'cc' : 'gcc', 'cxx' : 'g++', 'cflags' : '', 'cxxflags' : ''})
#b.build_library()

# OK
#b = Botan(arguments = {'source_archive_path' : '2.13.0.tar.gz', 'with_asm' : True, 'cxx' : 'clang++', 'cxxflags' : '', 'architecture' : 'x64'})
#b.build_library()
