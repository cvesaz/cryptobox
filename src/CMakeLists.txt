###############
# Set sources #
###############
set(SOURCES	main.cpp
		cryptobox.cpp)

###############
# Set headers #
###############
set(HEADERS	cryptobox.hpp)

############################
# Add cryptobox executable #
############################
message("Adding executable for cryptobox...")
include_directories(${INCLUDE_PATHS})
add_executable(cryptobox ${SOURCES} ${HEADERS})
target_link_libraries(cryptobox ${LINKING_FLAGS})
message("   INCLUDE_PATHS: ${INCLUDE_PATHS}")
message("   LINKING_FLAGS: ${LINKING_FLAGS}")
