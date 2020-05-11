###############
# Set project #
###############
cmake_minimum_required(VERSION 3.0)
message("Running cmake for cryptobox project...")
project(cryptobox)

################
# Set platform #
################
if(APPLE)
	message("Build for apple...")
	add_definitions(-DAPPLE)
endif(APPLE)

######################
# Set configurations #
######################
message("Setting CXX_FLAGS and configurations...")
set(CMAKE_CONFIGURATION_TYPES DEBUG;RELEASE)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++14)
message("   CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG -g -O0)
message("   CMAKE_CXX_FLAGS_DEBUG: ${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_RELEASE -O3 -ffast-math)
set(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG)
message("   CMAKE_CXX_FLAGS_RELEASE: ${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
message("   Output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

#######################
# Add openssl library #
#######################
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
	set(INCLUDE_PATHS ${INCLUDE_PATHS} ${OPENSSL_INCLUDE_DIR})
	set(LINKING_FLAGS ${LINKING_FLAGS} ${OPENSSL_LIBRARIES})
else(OPENSSL_FOUND)
	message(FATAL_ERROR "openssl library not found!!!")
endif(OPENSSL_FOUND)

#####################
# Add src directory #
#####################
add_subdirectory(src)
