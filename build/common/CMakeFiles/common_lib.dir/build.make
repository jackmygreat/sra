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
include common/CMakeFiles/common_lib.dir/depend.make

# Include the progress variables for this target.
include common/CMakeFiles/common_lib.dir/progress.make

# Include the compile flags for this target's objects.
include common/CMakeFiles/common_lib.dir/flags.make

common/CMakeFiles/common_lib.dir/common_libbpf.c.o: common/CMakeFiles/common_lib.dir/flags.make
common/CMakeFiles/common_lib.dir/common_libbpf.c.o: ../common/common_libbpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object common/CMakeFiles/common_lib.dir/common_libbpf.c.o"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/common_lib.dir/common_libbpf.c.o   -c /root/sra/xsk_srv6_46/xsk_srv6/common/common_libbpf.c

common/CMakeFiles/common_lib.dir/common_libbpf.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/common_lib.dir/common_libbpf.c.i"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/common/common_libbpf.c > CMakeFiles/common_lib.dir/common_libbpf.c.i

common/CMakeFiles/common_lib.dir/common_libbpf.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/common_lib.dir/common_libbpf.c.s"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/common/common_libbpf.c -o CMakeFiles/common_lib.dir/common_libbpf.c.s

common/CMakeFiles/common_lib.dir/common_params.c.o: common/CMakeFiles/common_lib.dir/flags.make
common/CMakeFiles/common_lib.dir/common_params.c.o: ../common/common_params.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object common/CMakeFiles/common_lib.dir/common_params.c.o"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/common_lib.dir/common_params.c.o   -c /root/sra/xsk_srv6_46/xsk_srv6/common/common_params.c

common/CMakeFiles/common_lib.dir/common_params.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/common_lib.dir/common_params.c.i"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/common/common_params.c > CMakeFiles/common_lib.dir/common_params.c.i

common/CMakeFiles/common_lib.dir/common_params.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/common_lib.dir/common_params.c.s"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/common/common_params.c -o CMakeFiles/common_lib.dir/common_params.c.s

common/CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.o: common/CMakeFiles/common_lib.dir/flags.make
common/CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.o: ../common/common_user_bpf_xdp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object common/CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.o"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.o   -c /root/sra/xsk_srv6_46/xsk_srv6/common/common_user_bpf_xdp.c

common/CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.i"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/sra/xsk_srv6_46/xsk_srv6/common/common_user_bpf_xdp.c > CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.i

common/CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.s"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/sra/xsk_srv6_46/xsk_srv6/common/common_user_bpf_xdp.c -o CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.s

# Object files for target common_lib
common_lib_OBJECTS = \
"CMakeFiles/common_lib.dir/common_libbpf.c.o" \
"CMakeFiles/common_lib.dir/common_params.c.o" \
"CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.o"

# External object files for target common_lib
common_lib_EXTERNAL_OBJECTS =

common/libcommon_lib.a: common/CMakeFiles/common_lib.dir/common_libbpf.c.o
common/libcommon_lib.a: common/CMakeFiles/common_lib.dir/common_params.c.o
common/libcommon_lib.a: common/CMakeFiles/common_lib.dir/common_user_bpf_xdp.c.o
common/libcommon_lib.a: common/CMakeFiles/common_lib.dir/build.make
common/libcommon_lib.a: common/CMakeFiles/common_lib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/sra/xsk_srv6_46/xsk_srv6/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C static library libcommon_lib.a"
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && $(CMAKE_COMMAND) -P CMakeFiles/common_lib.dir/cmake_clean_target.cmake
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/common_lib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
common/CMakeFiles/common_lib.dir/build: common/libcommon_lib.a

.PHONY : common/CMakeFiles/common_lib.dir/build

common/CMakeFiles/common_lib.dir/clean:
	cd /root/sra/xsk_srv6_46/xsk_srv6/build/common && $(CMAKE_COMMAND) -P CMakeFiles/common_lib.dir/cmake_clean.cmake
.PHONY : common/CMakeFiles/common_lib.dir/clean

common/CMakeFiles/common_lib.dir/depend:
	cd /root/sra/xsk_srv6_46/xsk_srv6/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/sra/xsk_srv6_46/xsk_srv6 /root/sra/xsk_srv6_46/xsk_srv6/common /root/sra/xsk_srv6_46/xsk_srv6/build /root/sra/xsk_srv6_46/xsk_srv6/build/common /root/sra/xsk_srv6_46/xsk_srv6/build/common/CMakeFiles/common_lib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : common/CMakeFiles/common_lib.dir/depend

