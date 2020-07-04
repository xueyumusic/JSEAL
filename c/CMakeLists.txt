cmake_minimum_required(VERSION 3.12)

project(JSEAL VERSION 3.4.5 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${JSEAL_SOURCE_DIR}/../bin)

add_library(sealjnr SHARED)
target_sources(sealjnr
    PRIVATE
	encparam.cpp
	modulus.cpp
	context.cpp
        keygenerator.cpp
        encryptor.cpp
        decryptor.cpp
        evaluator.cpp
        ckksencoder.cpp
        plaintext.cpp
        ciphertext.cpp
        public_key.cpp
        secret_key.cpp
        relin_keys.cpp
        galois_keys.cpp
        batchencoder.cpp
	integerencoder.cpp
)

# Import Microsoft SEAL
find_package(SEAL 3.4.5 EXACT REQUIRED)

# Link Microsoft SEAL
target_link_libraries(sealjnr SEAL::seal)
set_target_properties(sealjnr PROPERTIES VERSION 1.0.0 SOVERSION 1)
INSTALL(TARGETS sealjnr LIBRARY DESTINATION lib) 
