cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(kubridge C ASM)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -nostdlib -fno-optimize-sibling-calls")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

if(DEFINED EXCEPTION_SAFETY)
  set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -DEXCEPTION_SAFETY=${EXCEPTION_SAFETY}")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEXCEPTION_SAFETY=${EXCEPTION_SAFETY}")
endif(DEFINED EXCEPTION_SAFETY)

add_executable(kubridge
  src/main.c
  src/exceptions.c
  src/exceptions.S
  src/exceptions_bootstrap.S
  src/mprotect.c
  src/rwx_patch.S
)

target_link_libraries(kubridge
  taihenForKernel_stub
  taihenModuleUtils_stub
  SceCpuForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceProcEventForDriver_stub
  SceThreadmgrForDriver_stub
  SceDebugForDriver_stub
  SceSysrootForKernel_stub
  SceProcessmgrForDriver_stub
)

vita_create_self(kubridge.skprx kubridge CONFIG exports.yml UNSAFE)

vita_create_stubs(stubs kubridge ${CMAKE_CURRENT_SOURCE_DIR}/exports.yml KERNEL)

add_custom_target(kubridge_all
  ALL
  DEPENDS libkubridge_stub.a
  DEPENDS libkubridge_stub_weak.a
)

install(DIRECTORY ${CMAKE_BINARY_DIR}/stubs/
  DESTINATION lib
  FILES_MATCHING PATTERN "*.a"
)

install(FILES kubridge.h
  DESTINATION include
)
