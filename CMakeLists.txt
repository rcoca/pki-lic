project(license-lib)
cmake_minimum_required(VERSION 2.8)

if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftemplate-backtrace-limit=0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall  -pedantic")
endif()

if(WIN32)
    set(OPENSSL_ROOT_DIR "c:/OpenSSL-Win32-static/")
    set(CMAKE_MODULE_PATH cmake ${CMAKE_MODULE_PATH})
endif()

find_package(OpenSSL REQUIRED STATIC)
message(STATUS "Openssl Includes: ${OPENSSL_INCLUDE_DIRS}")
message(STATUS "OpenSSL libraries:${OPENSSL_LIBRARIES} - ${OPENSSL_LIBRARY_DIR}")
set(LICENSE_LIB_LIST certVerify.cpp)


INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/generated)

add_library(x509license STATIC
    ${LICENSE_LIB_LIST}
)

SET_TARGET_PROPERTIES(x509license PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(x509license ${OPENSSL_LIBRARIES})

set(CONVERTOR_SRCS x509_to_cxx.cpp)
add_executable(x509_to_cxx ${CONVERTOR_SRCS})
SET_TARGET_PROPERTIES(x509_to_cxx PROPERTIES LINKER_LANGUAGE CXX)


set(TEST_SRCS
    generated/caCertificate.cpp
    generated/xClientCertificate.cpp
    testVerify.cpp
)
add_executable(test_verify ${TEST_SRCS})
target_link_libraries(test_verify x509license ${OPENSSL_LIBRARIES})
