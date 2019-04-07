cmake_minimum_required(VERSION 2.6)
project(ykchalresp-nfc)
set(ykchalresp-nfc_VERSION_MAJOR 0)
set(ykchalresp-nfc_VERSION_MINOR 1)
set(ykchalresp-nfc_VERSION_PATCH 0)

if(APPLE)
    # Fix linking on 10.14+. See https://stackoverflow.com/questions/54068035
    link_directories(/usr/local/lib)
    include_directories(/usr/local/include)

    find_library(LIBNFC nfc)
    if(NOT LIBNFC)
        message(FATAL_ERROR "libnfc not found!")
    endif()
    find_library(LIBUSB usb)
    if(NOT LIBUSB)
        message(FATAL_ERROR "libusb not found!")
    endif()

    set(LIBNFC_LIBRARIES "nfc;usb")
else()
    find_package(LibNFC REQUIRED)
    include_directories("${LIBNFC_INCLUDE_DIRS}")
endif()

configure_file("${PROJECT_SOURCE_DIR}/ykchalresp-nfc.h.in"
               "${PROJECT_BINARY_DIR}/ykchalresp-nfc.h")
include_directories("${PROJECT_BINARY_DIR}")

add_executable(ykchalresp-nfc ykchalresp-nfc.c)
target_link_libraries(ykchalresp-nfc ${LIBNFC_LIBRARIES})
