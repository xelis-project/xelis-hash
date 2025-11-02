cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME xelishash_v3)

project(${PROJECT_NAME} C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")

add_subdirectory(BLAKE3/c)

set_source_files_properties(ChaCha20-SIMD/chacha20_sse2.c PROPERTIES COMPILE_FLAGS "-msse2")
set_source_files_properties(ChaCha20-SIMD/chacha20_avx2.c PROPERTIES COMPILE_FLAGS "-mavx2")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Enable AES-NI and PCLMUL instructions for all targets
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-maes -mpclmul)
elseif (MSVC)
    add_compile_options(/arch:AVX)
endif()

set(SOURCES
    ChaCha20-SIMD/chacha20.c
    ChaCha20-SIMD/chacha20_sse2.c
    ChaCha20-SIMD/chacha20_avx2.c
    ChaCha20-SIMD/chacha20_dispatch.c
    ChaCha20-SIMD/cpu_features.c
    xelis_hash_v3.c
)


add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} blake3 pthread m)



