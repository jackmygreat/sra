# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/sra/xsk_srv6_46/xsk_srv6

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/sra/xsk_srv6_46/xsk_srv6/build

# Include any dependencies generated for this target.
include CMakeFiles/xsk_srv6.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/xsk_srv6.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/xsk_srv6.dir/flags.make

CMakeFiles/xsk_srv6.dir/main.c.o: CMakeFiles/xsk_srv6.dir/flags.make
CMakeFiles/xsk_srv6.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/xsk_srv6.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/xsk_srv6.dir/main.c.o   -c /root/sra/xsk_srv6_46/xsk_srv6/main.c

CMakeFiles/xsk_srv6.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/xsk_srv6.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/main.c > CMakeFiles/xsk_srv6.dir/main.c.i

CMakeFiles/xsk_srv6.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/xsk_srv6.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/main.c -o CMakeFiles/xsk_srv6.dir/main.c.s

# Object files for target xsk_srv6
xsk_srv6_OBJECTS = \
"CMakeFiles/xsk_srv6.dir/main.c.o"

# External object files for target xsk_srv6
xsk_srv6_EXTERNAL_OBJECTS =

xsk_srv6: CMakeFiles/xsk_srv6.dir/main.c.o
xsk_srv6: CMakeFiles/xsk_srv6.dir/build.make
xsk_srv6: common/libcommon_lib.a
xsk_srv6: radix_fib/libradix_fib_lib.a
xsk_srv6: CMakeFiles/xsk_srv6.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable xsk_srv6"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/xsk_srv6.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/xsk_srv6.dir/build: xsk_srv6

.PHONY : CMakeFiles/xsk_srv6.dir/build

CMakeFiles/xsk_srv6.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/xsk_srv6.dir/cmake_clean.cmake
.PHONY : CMakeFiles/xsk_srv6.dir/clean

CMakeFiles/xsk_srv6.dir/depend:
	cd /root/sra/xsk_srv6_46/xsk_srv6/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/sra/xsk_srv6_46/xsk_srv6 /root/sra/xsk_srv6_46/xsk_srv6 /root/sra/xsk_srv6_46/xsk_srv6/build /root/sra/xsk_srv6_46/xsk_srv6/build /root/sra/xsk_srv6_46/xsk_srv6/build/CMakeFiles/xsk_srv6.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/xsk_srv6.dir/depend

