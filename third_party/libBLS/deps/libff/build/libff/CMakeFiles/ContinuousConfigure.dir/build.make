# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/build

# Utility rule file for ContinuousConfigure.

# Include the progress variables for this target.
include libff/CMakeFiles/ContinuousConfigure.dir/progress.make

libff/CMakeFiles/ContinuousConfigure:
	cd /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/build/libff && /usr/local/bin/ctest -D ContinuousConfigure

ContinuousConfigure: libff/CMakeFiles/ContinuousConfigure
ContinuousConfigure: libff/CMakeFiles/ContinuousConfigure.dir/build.make

.PHONY : ContinuousConfigure

# Rule to build all files generated by this target.
libff/CMakeFiles/ContinuousConfigure.dir/build: ContinuousConfigure

.PHONY : libff/CMakeFiles/ContinuousConfigure.dir/build

libff/CMakeFiles/ContinuousConfigure.dir/clean:
	cd /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/build/libff && $(CMAKE_COMMAND) -P CMakeFiles/ContinuousConfigure.dir/cmake_clean.cmake
.PHONY : libff/CMakeFiles/ContinuousConfigure.dir/clean

libff/CMakeFiles/ContinuousConfigure.dir/depend:
	cd /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/libff /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/build /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/build/libff /root/work/Tenon-BlockChain/third_party/libBLS/deps/libff/build/libff/CMakeFiles/ContinuousConfigure.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libff/CMakeFiles/ContinuousConfigure.dir/depend

