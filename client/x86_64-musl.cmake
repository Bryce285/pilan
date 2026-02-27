set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER /opt/musl/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc)
set(CMAKE_CXX_COMPILER /opt/musl/x86_64-linux-musl-cross/bin/x86_64-linux-musl-g++)

set(CMAKE_SYSROOT /opt/musl/x86_64-sysroot)

set(BUILD_SHARED_LIBS OFF)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(CMAKE_EXE_LINKER_FLAGS "-static")

set(ENV{PKG_CONFIG_LIBDIR} "${CMAKE_SYSROOT}/usr/lib/pkgconfig:${CMAKE_SYSROOT}/usr/local/lib/pkgconfig")
set(ENV{PKG_CONFIG_SYSROOT_DIR} "${CMAKE_SYSROOT}")
