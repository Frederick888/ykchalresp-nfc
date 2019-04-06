cmake_minimum_required (VERSION 2.6)
project (ykchalresp-nfc)
set (Tutorial_VERSION_MAJOR 1)
set (Tutorial_VERSION_MINOR 0)

find_package(LibNFC REQUIRED)
include_directories("${LIBNFC_INCLUDE_DIRS}")

add_executable(ykchalresp-nfc ykchalresp-nfc.c)
target_link_libraries(ykchalresp-nfc ${LIBNFC_LIBRARIES})
