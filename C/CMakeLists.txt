cmake_minimum_required(VERSION 3.10)

project(xelishash_v3 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_subdirectory(BLAKE3/c)

set(SOURCES
  ChaCha20-SIMD/chacha20.c
  ChaCha20-SIMD/chacha20_sse2.c
  ChaCha20-SIMD/chacha20_avx2.c
  ChaCha20-SIMD/chacha20_dispatch.c
  ChaCha20-SIMD/cpu_features.c
  xelis_hash_v3.c
)

# Per-file ISA flags
if(MSVC)
  set_source_files_properties(ChaCha20-SIMD/chacha20_avx2.c PROPERTIES COMPILE_FLAGS "/arch:AVX2")
else()
  set_source_files_properties(ChaCha20-SIMD/chacha20_sse2.c PROPERTIES COMPILE_FLAGS "-msse2")
  set_source_files_properties(ChaCha20-SIMD/chacha20_avx2.c PROPERTIES COMPILE_FLAGS "-mavx2")
endif()

add_executable(${PROJECT_NAME} ${SOURCES})

# Target flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(${PROJECT_NAME} PRIVATE -O3)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-6]86")
    target_compile_options(${PROJECT_NAME} PRIVATE -maes -mpclmul)
  endif()
elseif(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE /O2)
endif()

# Link
if(UNIX AND NOT APPLE)
  target_link_libraries(${PROJECT_NAME} PRIVATE blake3 pthread m)
else()
  target_link_libraries(${PROJECT_NAME} PRIVATE blake3)
endif()