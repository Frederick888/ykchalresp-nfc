cmake_minimum_required (VERSION 2.6)
project (ykchalresp-nfc)
set (Tutorial_VERSION_MAJOR 1)
set (Tutorial_VERSION_MINOR 0)

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

add_executable(ykchalresp-nfc ykchalresp-nfc.c)
target_link_libraries(ykchalresp-nfc ${LIBNFC_LIBRARIES})
