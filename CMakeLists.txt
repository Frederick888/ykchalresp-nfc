cmake_minimum_required(VERSION 3.0)
project(ykchalresp-nfc VERSION 0.1.0 LANGUAGES "C")

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

find_program(GENGETOPT gengetopt)
if(NOT GENGETOPT)
    message(FATAL_ERROR "gengetopt not found!")
endif()

configure_file("${PROJECT_SOURCE_DIR}/cmdline.ggo.in"
               "${PROJECT_BINARY_DIR}/cmdline.ggo")
add_custom_command(OUTPUT "${PROJECT_BINARY_DIR}/cmdline.h"
                          "${PROJECT_BINARY_DIR}/cmdline.c"
                   COMMAND "${GENGETOPT}" -i "${PROJECT_BINARY_DIR}/cmdline.ggo"
                           --file-name "cmdline"
                           --output-dir "${PROJECT_BINARY_DIR}"
                   DEPENDS "${PROJECT_BINARY_DIR}/cmdline.ggo")
include_directories("${PROJECT_BINARY_DIR}")

add_executable(ykchalresp-nfc ykchalresp-nfc.c "${PROJECT_BINARY_DIR}/cmdline.c")
target_link_libraries(ykchalresp-nfc ${LIBNFC_LIBRARIES})
