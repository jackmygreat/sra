# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /root/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/212.5457.51/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /root/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/212.5457.51/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/sra/xsk_srv6_46/xsk_srv6

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug

# Include any dependencies generated for this target.
include radix_fib/CMakeFiles/radix_fib_lib.dir/depend.make
# Include the progress variables for this target.
include radix_fib/CMakeFiles/radix_fib_lib.dir/progress.make

# Include the compile flags for this target's objects.
include radix_fib/CMakeFiles/radix_fib_lib.dir/flags.make

radix_fib/CMakeFiles/radix_fib_lib.dir/arp_table.c.o: radix_fib/CMakeFiles/radix_fib_lib.dir/flags.make
radix_fib/CMakeFiles/radix_fib_lib.dir/arp_table.c.o: ../radix_fib/arp_table.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object radix_fib/CMakeFiles/radix_fib_lib.dir/arp_table.c.o"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/radix_fib_lib.dir/arp_table.c.o -c /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/arp_table.c

radix_fib/CMakeFiles/radix_fib_lib.dir/arp_table.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/radix_fib_lib.dir/arp_table.c.i"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/arp_table.c > CMakeFiles/radix_fib_lib.dir/arp_table.c.i

radix_fib/CMakeFiles/radix_fib_lib.dir/arp_table.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/radix_fib_lib.dir/arp_table.c.s"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/arp_table.c -o CMakeFiles/radix_fib_lib.dir/arp_table.c.s

radix_fib/CMakeFiles/radix_fib_lib.dir/function.c.o: radix_fib/CMakeFiles/radix_fib_lib.dir/flags.make
radix_fib/CMakeFiles/radix_fib_lib.dir/function.c.o: ../radix_fib/function.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object radix_fib/CMakeFiles/radix_fib_lib.dir/function.c.o"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/radix_fib_lib.dir/function.c.o -c /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/function.c

radix_fib/CMakeFiles/radix_fib_lib.dir/function.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/radix_fib_lib.dir/function.c.i"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/function.c > CMakeFiles/radix_fib_lib.dir/function.c.i

radix_fib/CMakeFiles/radix_fib_lib.dir/function.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/radix_fib_lib.dir/function.c.s"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/function.c -o CMakeFiles/radix_fib_lib.dir/function.c.s

radix_fib/CMakeFiles/radix_fib_lib.dir/radix.c.o: radix_fib/CMakeFiles/radix_fib_lib.dir/flags.make
radix_fib/CMakeFiles/radix_fib_lib.dir/radix.c.o: ../radix_fib/radix.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object radix_fib/CMakeFiles/radix_fib_lib.dir/radix.c.o"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/radix_fib_lib.dir/radix.c.o -c /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/radix.c

radix_fib/CMakeFiles/radix_fib_lib.dir/radix.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/radix_fib_lib.dir/radix.c.i"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/radix.c > CMakeFiles/radix_fib_lib.dir/radix.c.i

radix_fib/CMakeFiles/radix_fib_lib.dir/radix.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/radix_fib_lib.dir/radix.c.s"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/radix.c -o CMakeFiles/radix_fib_lib.dir/radix.c.s

radix_fib/CMakeFiles/radix_fib_lib.dir/radix_fib.c.o: radix_fib/CMakeFiles/radix_fib_lib.dir/flags.make
radix_fib/CMakeFiles/radix_fib_lib.dir/radix_fib.c.o: ../radix_fib/radix_fib.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object radix_fib/CMakeFiles/radix_fib_lib.dir/radix_fib.c.o"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/radix_fib_lib.dir/radix_fib.c.o -c /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/radix_fib.c

radix_fib/CMakeFiles/radix_fib_lib.dir/radix_fib.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/radix_fib_lib.dir/radix_fib.c.i"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/radix_fib.c > CMakeFiles/radix_fib_lib.dir/radix_fib.c.i

radix_fib/CMakeFiles/radix_fib_lib.dir/radix_fib.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/radix_fib_lib.dir/radix_fib.c.s"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/radix_fib/radix_fib.c -o CMakeFiles/radix_fib_lib.dir/radix_fib.c.s

# Object files for target radix_fib_lib
radix_fib_lib_OBJECTS = \
"CMakeFiles/radix_fib_lib.dir/arp_table.c.o" \
"CMakeFiles/radix_fib_lib.dir/function.c.o" \
"CMakeFiles/radix_fib_lib.dir/radix.c.o" \
"CMakeFiles/radix_fib_lib.dir/radix_fib.c.o"

# External object files for target radix_fib_lib
radix_fib_lib_EXTERNAL_OBJECTS =

radix_fib/libradix_fib_lib.a: radix_fib/CMakeFiles/radix_fib_lib.dir/arp_table.c.o
radix_fib/libradix_fib_lib.a: radix_fib/CMakeFiles/radix_fib_lib.dir/function.c.o
radix_fib/libradix_fib_lib.a: radix_fib/CMakeFiles/radix_fib_lib.dir/radix.c.o
radix_fib/libradix_fib_lib.a: radix_fib/CMakeFiles/radix_fib_lib.dir/radix_fib.c.o
radix_fib/libradix_fib_lib.a: radix_fib/CMakeFiles/radix_fib_lib.dir/build.make
radix_fib/libradix_fib_lib.a: radix_fib/CMakeFiles/radix_fib_lib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C static library libradix_fib_lib.a"
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && $(CMAKE_COMMAND) -P CMakeFiles/radix_fib_lib.dir/cmake_clean_target.cmake
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/radix_fib_lib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
radix_fib/CMakeFiles/radix_fib_lib.dir/build: radix_fib/libradix_fib_lib.a
.PHONY : radix_fib/CMakeFiles/radix_fib_lib.dir/build

radix_fib/CMakeFiles/radix_fib_lib.dir/clean:
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib && $(CMAKE_COMMAND) -P CMakeFiles/radix_fib_lib.dir/cmake_clean.cmake
.PHONY : radix_fib/CMakeFiles/radix_fib_lib.dir/clean

radix_fib/CMakeFiles/radix_fib_lib.dir/depend:
	cd /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/sra/xsk_srv6_46/xsk_srv6 /root/sra/xsk_srv6_46/xsk_srv6/radix_fib /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib /root/sra/xsk_srv6_46/xsk_srv6/cmake-build-debug/radix_fib/CMakeFiles/radix_fib_lib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : radix_fib/CMakeFiles/radix_fib_lib.dir/depend

