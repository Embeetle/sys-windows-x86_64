'''
Copyright 2018-2024 Johan Cockx, Matic Kukovec and Kristof Mulier
'''
################################################################################
# SOURCE ANALYSER INTERFACE to EMBEETLE                                        #
#                                                                              #
# Please do not import any modules from Embeetle here.  Specifically, do not   #
# import purefunctions.  The source_analyzer module is not only used in        #
# Embeetle,  but also for regression testing.  During regression testing,      #
# Embeetle modules such as purefunctions are not available.  Also,  GUI        #
# functionality is not available.  This is an intentional design choice,  made #
# to keep the design of Embeetle and the source analyzer moduler and avoid     #
# circular dependencies.  Embeetle depends on the source analyzer,  but the    #
# source analyzer does not depend on Embeetle.                                 #
################################################################################

from __future__ import annotations
from typing import *
import sys, os, ctypes, threading, traceback, functools, subprocess, platform
import enum, time

# When trace is True, all @export methods will print a line when they are
# entered and when they return.
trace = False

_debug_print = print if os.environ.get('SA_DEBUG') else None
_eprint_mutex = threading.Lock()
def _eprint(*args, **kwargs) -> None:
    if _debug_print:
        with _eprint_mutex:
            _debug_print(*args, **kwargs, flush=True)
    return

_start = time.time()
def _now():
    return time.time() - _start

def _tprint(msg):
    if _debug_print:
        _debug_print(f'{_now():.3f} {msg}', flush=True)

def command_list2string(list):
    # Assume all arguments are acceptable both for sh and for cmd.
    #
    # Cannot use shlex.quote here, because that is only correct for sh, not for
    # cmd. cmd does not interpret quotes. With cmd, the interpretation of
    # special characters on the command line depends on the command itself.
    # Many commands including `make` use the same conventions.
    #
    # Current quoting implementation is not perfect for all circumstances yet.
    
    def works_unquoted_in_any_shell(arg):
        return re.search(_quotes_needed_regex, arg) is None

    def quote(arg):
        if works_unquoted_in_any_shell(arg):
            return arg
        return '"' + arg.replace('"', '\\"') + '"'

    return ' '.join([quote(a) for a in list])

# Return a normalized path for a given path, such that two files or
# directories are equal iff their normalized paths are equal. A relative
# path is interpreted as relative to the given working directory, default '.'.
#
# If an anchor is given, the normalized path will be relative to the specified
# anchor directory instead of absolute. The anchor should be a string
# representing a path. If it is a relative path, it is again relative to the
# given working directory. If it starts with a drive letter (on windows), the
# drive letter must be the same as the drive letter of the path to be
# normalized, or else an absolute path is returned. There is no way on windows
# to specify a relative path to another drive.
#
# The normalized path always uses '/' as separator, even on windows, because
# Clang does not recognize `\` as a path separator. Windows handles this
# correctly, only the cmd shell doesn't.
#
# The case of letters in the path is not changed, even not for a case
# insensitive OS like windows.  The underlying reason is that we want to make
# sure that a project that works on windows also works on linux, so case should
# be used consistently.  The `make` command uses the same approach, even on
# windows, unless recompiled with different settings.
def _standard_path(path, workdir = '.', anchor = None):
    new_path = os.path.realpath(
        os.path.join(
            workdir,
            os.path.expanduser(os.path.expandvars(path))
        )
    )
    # For windows, normalize the drive letter by making it uppercase. This is a
    # no-op for linux and other Unix-like operating systems.
    new_path = new_path[0].upper() + new_path[1:]
    if anchor:
        # Try to create a relative path with respect to the anchor
        try:
            new_path = os.path.relpath(new_path, os.path.join(workdir, anchor))
        except ValueError:
            pass
    new_path = new_path.replace('\\', '/')
    return new_path

# Join normalized paths to normalized path
def _join_paths(*paths):
    return os.path.join(*paths).replace('\\', '/')

# Decorator for 'export' methods, i.e. methods of the Project class that are
# intended to be called from the application.
#
# - fallback: value to be returned when an exception occurs.
#
def export(function=None, *, fallback=None):
    def decorate(function):
        @functools.wraps(function)
        def wrapper(self, *args, **kwargs):
            if trace:
                args_repr = [
                    *[repr(a) for a in args],
                    *[f"{k}={v!r}" for k, v in kwargs.items()],
                ]
                _eprint(f'enter {function.__name__}({", ".join(args_repr)})')
            try:
                result = function(self, *args, **kwargs)
                if trace:
                    _eprint(f'leave {function.__name__}')
                return result
            except Exception as error:
                _eprint(f'error in {function.__name__}: {error}')
                traceback.print_exc()
                #raise error
                self.report_internal_error(traceback.format_exc())
                return fallback
        return wrapper
    if function:
        return decorate(function)
    else:
        return decorate

class ClangRestrictedCallbackError(Exception):
    pass
_active_restricted_callback_thread_ids = set()
_active_restricted_callback_mutex = threading.Lock()
def _internal_not_in_restricted_callback():
    if threading.get_ident() in _active_restricted_callback_thread_ids:
        raise ClangRestrictedCallbackError
def _check_not_in_restricted_callback():
    with _active_restricted_callback_mutex:
        _internal_not_in_restricted_callback()        
def _enter_restricted_callback(name):
    with _active_restricted_callback_mutex:
        _internal_not_in_restricted_callback()        
        _active_restricted_callback_thread_ids.add(threading.get_ident())
def _leave_restricted_callback(name):
    with _active_restricted_callback_mutex:
        _active_restricted_callback_thread_ids.remove(threading.get_ident())

class ProjectStatus(enum.Enum):
    READY = 0   # All files analyzed
    BUSY = 1    # Not all files analyzed yet, analysis is running
    ERROR = 2   # Analysis of at least one file failed
    
def project_status_name(status):
    return _decode( lib.ce_project_status_name(ProjectStatus(status).value) )
    
class LinkerStatus(enum.Enum):
    WAITING = 0
    BUSY = 1
    DONE = 2
    ERROR = 3

def linker_status_name(status):
    return _decode( lib.ce_linker_status_name(LinkerStatus(status).value) )
    
class FileMode(enum.Enum):
    EXCLUDE = 0
    INCLUDE = 1
    AUTOMATIC = 2

def file_mode_name(mode):
    return _decode( lib.ce_file_mode_name(FileMode(mode).value) )

# Backward compatibility:
file_mode_exclude = FileMode.EXCLUDE.value
file_mode_include = FileMode.INCLUDE.value
file_mode_automatic = FileMode.AUTOMATIC.value

class FileKind(enum.Enum):
    OTHER = 0
    EXECUTABLE = 1
    HEADER = 2
    ARCHIVE = 3
    OBJECT = 4
    ASSEMBLER = 5
    ASSEMBLER_WITH_CPP = 6
    C = 7
    CPLUSPLUS = 8

def file_kind_name(kind):
    return _decode( lib.ce_file_kind_name(kind.value) )

class HdirMode(enum.Enum):
    EXCLUDE = 0
    INCLUDE = 1
    AUTOMATIC = 2

def hdir_mode_name(mode):
    return ["exclude", "include", "automatic"][HdirMode(mode).value]
    
# Backward compatibility:
hdir_mode_exclude = HdirMode.EXCLUDE.value
hdir_mode_include = HdirMode.INCLUDE.value
hdir_mode_automatic = HdirMode.AUTOMATIC.value

class InclusionStatus(enum.Enum):
    EXCLUDED = 0
    INCLUDED = 1

# Backward compatibility:
inclusion_status_excluded = InclusionStatus.EXCLUDED.value
inclusion_status_included = InclusionStatus.INCLUDED.value

def inclusion_status_name(status):
    return _decode(lib.ce_inclusion_status_name(InclusionStatus(status).value))

# Analysis feedback per file:
class AnalysisStatus(enum.Enum):
    NONE = 0    # Analysis not required
    WAITING = 1 # Analysis scheduled
    BUSY = 2    # Analysis in progress
    DONE = 3    # Analysis done
    FAILED = 4  # Analysis failed
# Analysis fails if the file is unreadable or does not exist, analysis crashed,
# or flag extraction failed. An analysis that detects errors did not fail. It
# only fails when it cannot analyze the source files due to one of the above
# reasons.

def analysis_status_name(status):
    return _decode( lib.ce_analysis_status_name(AnalysisStatus(status).value) )
    
number_of_entity_kinds               = 25
all_entity_kinds = range(number_of_entity_kinds)

def entity_kind_name(kind):
    return _decode( lib.ce_entity_kind_name(kind) )

def symbol_kind_name(kind):
    return entity_kind_name(kind)

def entity_kind(name):
    for kind in all_entity_kinds:
        if entity_kind_name(kind) == name:
            return kind
    assert False

def print_all_entity_kinds():
    for kind in all_entity_kinds:
        print(f'{kind} {entity_kind_name(kind)}')

class OccurrenceKind(enum.Enum):
    DEFINITION = 0
    TENTATIVE_DEFINITION = 1
    WEAK_DEFINITION = 2
    DECLARATION = 3
    WEAK_DECLARATION = 4
    USE = 5
    WEAK_USE = 6
    INCLUDE = 7
    NONE = 8
    
occurrence_kind_definition = OccurrenceKind.DEFINITION.value
occurrence_kind_tentative_definition = OccurrenceKind.TENTATIVE_DEFINITION.value
occurrence_kind_weak_definition = OccurrenceKind.WEAK_DEFINITION.value
occurrence_kind_declaration = OccurrenceKind.DECLARATION.value
occurrence_kind_weak_declaration = OccurrenceKind.WEAK_DECLARATION.value
occurrence_kind_use = OccurrenceKind.USE.value
occurrence_kind_weak_use = OccurrenceKind.WEAK_USE.value
occurrence_kind_include = OccurrenceKind.INCLUDE.value
occurrence_kind_none = OccurrenceKind.NONE.value
number_of_occurrence_kinds = 8
all_definition_kinds = [
    occurrence_kind_definition,
    occurrence_kind_tentative_definition,
    occurrence_kind_weak_definition,
]
all_declaration_kinds = [
    occurrence_kind_declaration,
    occurrence_kind_weak_declaration,
]
all_use_kinds = [
    occurrence_kind_use,
    occurrence_kind_weak_use,
]
all_occurrence_kinds = range(number_of_occurrence_kinds)

def occurrence_kind_name(kind):
    return _decode( lib.ce_occurrence_kind_name(OccurrenceKind(kind).value) )

class LinkStatus(enum.Enum):
    NONE = 0
    WEAKLY_UNDEFINED = 1
    UNDEFINED = 2
    WEAKLY_DEFINED = 3
    DEFINED = 4
    MULTIPLY_DEFINED = 5
    
def link_status_name(value):
    return _decode( lib.ce_link_status_name(LinkStatus(value).value) )

class Severity(enum.Enum):
    WARNING = 0
    ERROR = 1
    FATAL = 2
    
# Backward compatibility
severity_warning = Severity.WARNING.value
severity_error = Severity.ERROR.value

def severity_name(value):
    return _decode( lib.ce_severity_name(Severity(value).value) )

class Category(enum.Enum):
    NONE = 0
    TOOLCHAIN = 1
    MAKEFILE = 2
    
def category_name(value):
    return _decode( lib.ce_category_name(Category(value).value) )

# Notes on garbage collection
#
# 1. Many of the callback functions below have a closure that contains a
#    reference to the Python object on which they are defined, and the Python
#    object has a reference to the callback. This reference cycle keeps the
#    object alive - even if there is no other reference to the object - until
#    garbage collection is triggered.  This is usually fine, as it avoids
#    destroying and recreating an object that is used several times in a short
#    time.  If necessary, more aggressive garbage collection can be achieved by
#    replacing "<object>._<callback>" by "get_<object>(handle)._<callback>"
#    below: in that case, the closure does not hold a reference to the object
#    anymore, so the object is collected as soon as its reference count
#    decreases to zero.
#
# 2. Do not use __del__ to unset user data.  There will always be a moment when
#    __del__ has been called but user data has not been dropped yet. If a
#    background thread accesses the user data at that moment and then passes it
#    to a callback, the user data will be deleted by the time the callback tries
#    to access it, causing a crash.
#
# 3. Do not use __del__ to call any C++ source analyzer function that locks the
#    project.  Garbage collection can be called at any time, including during a
#    callback during which the project is already locked.  Trying to lock it
#    again will cause a deadlock.
#
# Conclusion: do not use __del__

# Path of sys directory in the Embeetle installation. Only used for defaults.
_sys_path = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.realpath(__file__)
        )
    )
) + '/sys'

# OS name (linux or windows). Only used for defaults.
_osname = platform.system().lower()

class Project:
    # Default value for _handle in case __init__ fails with an exception
    _handle = None

    # Project constructor. 
    @export
    def __init__(
            self,
            project_path = '.',
            cache_path = '.beetle/.cache',
            run_function = subprocess.run,
            resource_path = _sys_path + '/esa',
            lib_path = _sys_path + '/' + _osname  + '/lib',
    ):
        '''Construct a SA project.

        :param project_path: Path to the root folder of the project. A relative
                             path is relative to the working directory.

        :param cache_path:   Path of the folder that will be used to cache SA
                             results. A relative path is relative to the project
                             root folder.

        :param run_function: Function used to run commands such as `make`
                             (in dry-run mode) or a compiler for flag
                             extraction.  This function should have the same API
                             as subprocess.run, and it defaults to
                             subprocess.run.

        :param resource_path: Path of the folder containing platform-independent
                             resource files for the source analyzer.

        :param lib_path:     Path of the folder containing platform-dependent
                             compiled code such as `clang`

        The following default values will be configured for the project:
          - make_command = ["make"]
          - env = os.environ
          - source_path = project_path
          - build_path = project_path
        These can be changed later using project methods.
        '''
        #_eprint(f"create project {path}")
        assert isinstance(project_path, str), project_path
        self.project_path = _standard_path(project_path)
        make_command = ["make"]
        env = os.environ
        self.source_path = self.project_path
        build_path = self.project_path
        self.build_path = build_path

        def flags_changed_notifier():
            self._request_flags_update()
        
        self._run = run_function

        # Set of user file objects to be kept alive
        self._file_objs = set()

        # File handles for all analyzed files, i.e. automatic files and included
        # files as well as excluded files for which occurrence information has
        # been requested.
        self._analyzed_files = set()

        # Mapping of hdir paths to hdir status, for hdirs that are not in
        # automatic mode and unused.
        self._hdir_table = {}

        # Hdir usage can be changed from different threads: the application by
        # setting the hdir mode and background source analysis threads using the
        # hdir usage callback.  To ensure correctness of the hdir status, all
        # accesses must be protected using this mutex.
        self._hdir_table_mutex = threading.Lock()

        # Mapping of hdir paths to hdir user objects.
        # The C++ code does not keep track of user data for hdirs.
        self._hdir_user_data_map = {}

        # C++ does not keep a reference to Python objects stored as user data.
        # Doing that would require some additional C++ code to decrement the
        # reference count when the user data is changed, and we would prefer not
        # to do that, as it would make the C++ code dependent on the Python
        # version.
        #
        # As a result, new Python objects, such as symbols created by the
        # add-symbol callback, have zero references and are garbage collected as
        # soon as the callback returns, unless we keep a reference somewhere in
        # Python. One option is to keep a set of objects - such as symbols - on
        # the project.
        #
        # The keep-alive set below is intended to be used for that purpose: to
        # temporarily keep Python objects alive, while a pointer to them is
        # being passed back to C++ user data but the object is not used in
        # Python yet.
        self._keep_alive:Set = set()
        
        self.diagnostic_set:Set = set()
        self.occurrence_set:Set = set()
        self.tracked_file_includes:Dict = {}
        self._progress_count:int = 0
        self._total_count:int = 0
        self._handle = _create_project(
            self.project_path, cache_path, self,
            resource_path, lib_path
        )
        #self._busy_files = set()

    @export
    def drop(self):
        #_eprint(f"project drop")
        _check_not_in_restricted_callback()
        lib.ce_drop_project(self._handle)
        self._handle = None

    # Change the `make` configuration. The make configuration consists of two
    # parts: the make command and the environment.
    #
    # The make command is a list of strings representing how the make command is
    # used to build the project, except that it should not contain any targets;
    # for example: ['make', '-f', 'makefile', 'TOOLPREFIX=tool_command_prefix']
    # with 'make', 'makefile' and 'tool_command_prefix' replaced by appropriate
    # values.
    #
    # The environment is a dictionary of environment variables, including the
    # PATH environment variable, that defines the environment in which the make
    # command will be executed. An easy way to construct an environment
    # dictionary starting from the current environment is to call
    # os.environ.copy() and modify the result.
    #
    @export
    def set_make_config(self, make_command, env = os.environ):
        #_eprint(f"set make command: {command_list2string(make_command)}")
        _set_make_command(self._handle, make_command, env)
        self._request_flags_update()
        for arg in make_command:
            if arg.startswith('TOOLPREFIX='):
                self.set_toolchain_prefix(arg[11:])
        return

    def set_toolchain_prefix(self, prefix):
        #_eprint(f"set toolchain prefix: {prefix}")
        _set_toolchain_prefix(self._handle, prefix)
        return

    # Set the path of the build directory, the directory where the make command
    # will be invoked. A relative build directory will be interpreted as
    # relative to the current working directory.
    @export
    def set_build_path(self, path):
        #_eprint(f"project set build path to {path}")
        # Uncomment next line to test internal error popup
        #assert False
        _set_build_path(self._handle, path)
        self.build_path = path
        self._request_flags_update()
        return

    @export
    def set_hdir_mode(self, path, mode, hdir_python_obj=None):
        '''
        Set the mode of an hdir. A relative hdir path is relative to the source
        directory (note: Kristof always passes absolute paths).

        :param path:    Path to the hdir (I, Kristof, always pass an absolute
                        path here).

        :param mode:    One of these (see definitions at the top of this file):
                            - hdir_mode_exclude = 0
                            - hdir_mode_include = 1
                            - hdir_mode_automatic = 2

        :param hdir_python_obj: [Optional] A Python object from the filetree.
        '''
        mode = HdirMode(mode)
        #_tprint(f'set hdir mode {path} {mode}')
        std_path = _standard_path(path, self.source_path)
        user_data = hdir_python_obj or std_path
        def report_hdir_usage(status):
            #_tprint(f" `-> report {inclusion_status_name(status)}")
            self.report_hdir_usage(user_data, status==InclusionStatus.INCLUDED)
        with self._hdir_table_mutex:
            hdir = self._get_hdir(std_path, user_data)
            #_tprint(
            #    f"set hdir mode for {std_path}"
            #    f" from {hdir.mode} {hdir_mode_name(hdir.mode)}"
            #    f" to {mode} {hdir_mode_name(mode)}"
            #)
            if hdir.mode != mode:
                if hdir.mode == HdirMode.EXCLUDE:
                    if (mode == HdirMode.INCLUDE or
                        hdir.status == InclusionStatus.INCLUDED
                    ):
                        report_hdir_usage(InclusionStatus.INCLUDED)
                elif hdir.mode == HdirMode.INCLUDE:
                    if (mode == HdirMode.EXCLUDE or
                        hdir.status == InclusionStatus.EXCLUDED
                    ):
                        report_hdir_usage(InclusionStatus.EXCLUDED)
                else: # hdir.mode == HdirMode.AUTOMATIC
                    if mode == HdirMode.EXCLUDE:
                        if hdir.status == InclusionStatus.INCLUDED:
                            report_hdir_usage(InclusionStatus.EXCLUDED)
                    else: # mode == HdirMode.INCLUDE
                        if hdir.status == InclusionStatus.EXCLUDED:
                            report_hdir_usage(InclusionStatus.INCLUDED)
                hdir.mode = mode
                self._try_drop_hdir(path, hdir)
        if mode == HdirMode.EXCLUDE:
            self._remove_hdir(std_path)
        else:
            self._add_hdir(std_path)

    # Callback from analysis when hdir usage has changed.
    def _set_hdir_usage(self, std_path, status):
        with self._hdir_table_mutex:
            #_tprint(f'set hdir {std_path} {status}')
            hdir = self._get_hdir(std_path)
            assert hdir.status != status
            hdir.status = status
            #_tprint(f'mode={hdir_mode_name(hdir.mode)}')
            if hdir.mode == HdirMode.AUTOMATIC:
                #_tprint(f' `-> report {inclusion_status_name(status)}')
                self.report_hdir_usage(
                    hdir.user_data, status == InclusionStatus.INCLUDED
                )
            self._try_drop_hdir(std_path, hdir)

    # Get hdir from table or default.  Assume mutex is locked.
    def _get_hdir(self, std_path, user_data=None):
        hdir = self._hdir_table.get(std_path, None)
        if not hdir:
            hdir = Hdir(user_data or std_path)
            self._hdir_table[std_path] = hdir
        return hdir

    # Drop hdir from table if mode is equal to default. Assume mutex is locked.
    def _try_drop_hdir(self, std_path, hdir):
        if hdir.mode == HdirMode.EXCLUDE:
            if hdir.status == inclusion_status_excluded:
                self._hdir_table.pop(std_path)

    # Add an hdir to the include search path.  A relative hdir path is relative
    # to the source directory.
    def _add_hdir(self, std_path, hdir_python_obj=None):
        #_tprint(f'add hdir {std_path}')
        _check_not_in_restricted_callback()
        lib.ce_add_hdir(self._handle, _encode(std_path), hdir_python_obj)
        #_tprint(f'add hdir {std_path} done')
        
    # Remove an hdir to the include search path.  A relative hdir path is
    # relative to the source directory.
    def _remove_hdir(self, std_path):
        #_tprint(f'remove hdir {std_path}')
        _check_not_in_restricted_callback()
        lib.ce_remove_hdir(self._handle, _encode(std_path))
        #_tprint(f'remove hdir {std_path} done')

    def _is_binary_file(self, path):
        root, extension = os.path.splitext(path)
        return extension in [ '.o', '.a', '.obj', '.so', '.dll' ]

    def _register_for_analysis(self, path, file_handle):
        kind = _get_file_kind(file_handle)
        if kind in (FileKind.C, FileKind.CPLUSPLUS, FileKind.ASSEMBLER,
                    FileKind.ASSEMBLER_WITH_CPP
        ):
            #_tprint(f'register for {kind} analysis: {path}')
            self._analyzed_files.add(file_handle)

    def _unregister_for_analysis(self, path, file_handle):
        #_tprint(f'unregister for analysis: {path}')
        self._analyzed_files.discard(file_handle)

    @export
    def add_file(self, path, mode=FileMode.AUTOMATIC, file_python_obj=None):
        '''
        Add a file to the project if it wasn't in the project yet.  Also set the 
        file's mode and the Python object to be used in callbacks related to
        this file.

        :param path:    Path to the file. A relative path is relative to the
                        project directory. Kristof always passes absolute paths.

        :param mode:    New mode for the file. One of these (as defined above):
                          - FileMode.EXCLUDE
                          - FileMode.INCLUDE
                          - FileMode.AUTOMATIC

        :param file_python_obj:     Python object to be used in callbacks
                                    If none, the file's path (a string) will be 
                                    used instead.
        '''
        mode = FileMode(mode)
        #_tprint(f'project add file {path} ({file_mode_name(mode)})')
        file_handle = self._get_file_handle(path)
        #
        # Keep the file object alive even when not referenced anymore from user
        # code.  It can still be used in callbacks from C++. C++ will issue a
        # drop_file callback when it will no longer use the file object.
        user_data = _get_file_user_data(file_handle)
        if user_data != file_python_obj:
            if user_data:
                self._file_objs.remove(user_data)
            if file_python_obj:
                self._file_objs.add(file_python_obj)
        #
        _add_file(file_handle, mode, file_python_obj)
        if mode in (FileMode.AUTOMATIC, FileMode.INCLUDE):
            self._register_for_analysis(path, file_handle)
        _drop_file_handle(file_handle)

    @export
    def get_file_kind(self, path):
        file_handle = self._get_file_handle(path)
        kind = _get_file_kind(file_handle)
        _drop_file_handle(file_handle)
        return FileKind(kind)

    @export
    def set_file_mode(self, path, mode):
        '''
        Change the mode of a previously added file.

        :param path:     Path to the file. A relative path is relative to the
                         project directory. Kristof always passes absolute paths.

        :param mode:     New mode for the file. One of these (as defined above):
                          - FileMode.EXCLUDE
                          - FileMode.INCLUDE
                          - FileMode.AUTOMATIC
        '''
        mode = FileMode(mode)
        #_tprint(f'project set file mode {path} ({file_mode_name(mode)})')
        file_handle = self._get_file_handle(path)
        _set_file_mode(file_handle, mode)
        if mode in (FileMode.AUTOMATIC, FileMode.INCLUDE):
            self._register_for_analysis(path, file_handle)
        _drop_file_handle(file_handle)

    @export
    def remove_file(self, path):
        '''
        Remove the file with the given path.

        :param path:    Path to the file.
        '''
        #_eprint(f'project remove file {path}')
        file_handle = self._get_file_handle(path)
        _remove_file(file_handle)
        self._unregister_for_analysis(path, file_handle)
        _drop_file_handle(file_handle)
        #_eprint(f'project removed file {path}')

    @export
    def get_file_includes(self, path):
        '''
        Get occurrences of #include's of a file
        
        :param path:     Path to the file. A relative path is relative to the
                         project directory.

        :return: A list of Occurrence objects.
        '''
        file_handle = self._get_file_handle(path)
        _track_occurrences_of_entity(file_handle, [occurrence_kind_include])
        includes = self.tracked_file_includes.get(file_handle, [])
        _track_occurrences_of_entity(file_handle, [])
        self.tracked_file_includes.pop(file_handle, None)
        _drop_file_handle(file_handle)
        return includes

    @export
    def get_file_include_locations(self, path):
        return self.get_file_includes(path)
        
    @export
    def file_analysis_data_was_read_from_cache(self, path):
        '''

        '''
        file_handle = self._get_file_handle(path)
        was = _file_analysis_data_was_read_from_cache(file_handle)
        _drop_file_handle(file_handle)
        return was

    # Reload the file with the given path, presumably because it has changed on
    # disk. If it is a C or C++ file, this will trigger a re-analysis of the
    # contents of this file. If it is a header file, it will trigger a
    # re-analysis of all files including this file. If it is a makefile or
    # included by a makefile, it will trigger a re-extraction of all flags.
    @export
    def reload_file(self, path):
        #_eprint(f"reload file {path}")
        #
        # We allow a file to be both a source file and a makefile. Although this
        # situation is improbable, the cost is low.
        #
        # Reload as source file.
        file_handle = self._get_file_handle(path)
        _reload_file(file_handle)
        _drop_file_handle(file_handle)

    # Reload all files including the makefile. Mainly useful in case of bugs.
    @export
    def reload_all(self):
        #_eprint("source_analyzer reload all")
        _check_not_in_restricted_callback()
        self._request_flags_update()
        for file_handle in self._analyzed_files:
            _reload_file(file_handle)

    @export
    def edit_file(self, path, begin_offset, end_offset, new_content):
        '''Notify the SA that a file has been edited.

        Calling this function allows the SA to fix the location of occurrences
        after the edit location.  In the future, it may also allow the SA to
        re-analyze the file without saving it.

        This function can may be called multiple times, for a cumulative effect.
        Reloading the file (by calling the reload_file function) resets the
        effect of edits and re-analyzes the file as stored on disk.

        :param path:       Path to the file. A relative path is relative to the
                           project directory.

        :param begin_offset: Byte offset of the first changed byte

        :param end_offset: Byte offset of the first byte after the change

        :param new_text: The text that replaces the text in the edited range.
                           The length can differ from the length of the edited
                           range; this allows the edit_file function to be used
                           for insertion (empty range), deletion (empty
                           new_text) or combined (replacement) edits.
        '''
        file_handle = self._get_file_handle(path)
        _edit_file(file_handle, begin_offset, end_offset, new_content)
        _drop_file_handle(file_handle)
        
    # Return an object describing the entity overlapping a given range
    # (specified as offset and tolerances) in a given file, or None if no
    # entity is found at that location.
    #
    # The returned object is constructed by 'user_occurrence(...)'; see there
    # for details. A tolerance of zero only matches the exact location. A
    # tolerance of n also matches the n preceding and following characters on
    # the same line.
    #
    @export
    def find_occurrence(self, path, offset, begin_tol=0, end_tol=1):
        _check_not_in_restricted_callback()
        #_tprint(f'find occurrence at {offset}-{begin_tol}+{end_tol}')
        file_handle = self._get_file_handle(path)
        self._register_for_analysis(path, file_handle)
        data = lib.ce_find_occurrence(file_handle, offset, begin_tol, end_tol)
        #_tprint(f"kind: {data.kind} {occurrence_kind_name(data.kind)}")
        if data.kind == occurrence_kind_none:
            #_tprint(f"At {offset}: no occurrence found")
            _drop_file_handle(file_handle)
            return None
        occurrence = user_occurrence(
            _decode(data.path), data.begin_offset, data.end_offset,
            data.kind, data.entity, data.entity_handle, data.linked
        )
        #_tprint(f'found {data.begin_offset} - {data.end_offset}')
        if data.kind != occurrence_kind_include:
            # Entity is a symbol,  not a file; update its occurrence lists
            occurrence.symbol._load_occurrence_lists(data.entity_handle)
        _drop_entity_handle(data.entity_handle)
        _drop_file_handle(file_handle)
        #_tprint(f"At {offset}: {occurrence}")
        return occurrence

    # Find symbols with given name
    @export
    def find_symbols(self, name:str) -> List[Symbol]:
        '''
        Get a list of included symbols with a given name.

        :param name:    Name of symbols to be returned.

        :return: A list of Python Symbol objects.
        '''
        symbols:List[Symbol] = []
        @FindSymbol_callback
        def find_symbol(symbol_id, symbol_handle, user_data):
            symbol = _py_object(symbol_id)
            symbol._load_occurrence_lists(symbol_handle)
            symbols.append(symbol)
            #drop_entity_handle(symbol_handle)
        _check_not_in_restricted_callback()
        lib.ce_find_symbols(self._handle, _encode(name), find_symbol, None)
        #_eprint(f"Found symbols {[str(symbol) for symbol in symbols]}")
        #for symbol in symbols:
        #    locs = ' '.join([ str(loc)
        #               for loc in symbol.definitions + symbol.weak_definitions
        #    ])
        #    _eprint(f'Found symbol {symbol} {locs}')
        return symbols

    # Get completions
    @export
    def get_completions(self, path, pos, context):
        '''Get possible completions at a given position in a source file.

        :param path:    Path of the file in which to get completions

        :param pos:     Byte offset in that file at which to get completions

        :param context: A string containing part of the content of the file up
                        to the completion position. Suggestion is to provide at
                        least the line of the completion position, and maybe
                        also the line before it. More is allowed and may lead to
                        better completions, but there is a trade-off: giving too
                        much data will slow down this call. The last character
                        in this string should be the character just before the
                        completion position.

        :return: A tuple consisting of an insertion position and a list of
                 completion strings.  To apply a completion, replace the
                 existing text from insertion position to completion position by
                 the completion string.

        Example: suppose the user types this line in foo.c:

          foo = get_

        and you want to get possible completions after the underscore. If the 
        byte offset at the cursor - just after the underscore - is 110,  you
        make this call:

          get_completions("foo.c", 110, "  foo = get_")

        This might return two completions as: (106, ["get_key()","get_value()"])
        To apply the first completion, replace existing text from position (byte
        offset) 106 to 110 ("get_") by "get_key()".
        '''
        #_eprint(f"get completions {path} {pos} {context}")
        completions = []
        @AddCompletion_callback
        def add_completion(raw_completion, user_data):
            completion = _decode(raw_completion)
            #_eprint(f"Add completion: {completion}")
            completions.append(completion)
            
        _check_not_in_restricted_callback()
        file_handle = self._get_file_handle(path)
        insert_pos = lib.ce_get_completions(
            file_handle, pos, add_completion, None, _encode(context),
        )
        #_eprint(f"Completions: {pos}-{pos-insert_pos} {completions}")
        return insert_pos, completions

    # Set occurrence tracking filter for file
    @export
    def track_occurrences(self, path, occurrence_kinds, entity_kinds):
        _check_not_in_restricted_callback()
        file_handle = self._get_file_handle(path)
        self._register_for_analysis(path, file_handle)
        lib.ce_track_occurrences_in_file(
            file_handle,
            _list_to_bitset(occurrence_kinds),
            _list_to_bitset(entity_kinds),
        )
        _drop_file_handle(file_handle)

    # Callback from source analyzer to add a tracked occurrence.  Initially,
    # there are no tracked occurrences.  All changes are reported using
    # callbacks to add and remove tracked occurrences. This add occurrence
    # callback takes an Occurrence (see further) object as parameter and should
    # return a Python object (of any type) that uniquely identifies the
    # occurrence to the application. The call to remove the occurrence will get
    # this object as a parameter. The default implementation does nothing.
    #
    # The data object is either an IncludeOccurrence or a SymbolOccurrence,
    # depending on data.kind. These are the same objects that are returned by
    # find_occurrence.
    #
    # The scope is either None or a previously returned Python object for the
    # containing occurrence. The containing occurrence is always a definition;
    # it can be a function, struct or any kind of entity that can have nested
    # symbols.
    def add_occurrence(self, data, scope):
        pass

    # Callback from source analyzer to remove a tracked occurrence previously
    # added by the add occurrence callback. The parameter is the Python object
    # returned by the add occurrence callback. The default implementation does
    # nothing.
    def remove_occurrence(self, occurrence):
       pass

    # Report the number of tracked occurrences. This may be larger than the
    # number of reported occurrences, due to a tracking limit.
    def report_occurrences_count(self, count):
        pass

    def set_alternative_content(self, path, content):
        '''
        Callback from source analyzer to set alternative content for a binary
        file (type OBJECT or ARCHIVE). When alternative content is set,
        occurrence offsets refer to the alternative content instead of to the
        actual file content.
    
        This function is called when at least one occurrence kind is tracked and
        the content changes. Existing occurrences remain valid after this call,
        unless removed by remove_occurrence.

        file -- the file object given when this file was added, or the path of
                the source file if no file object was given

        content -- the alternative file content
        '''
        pass

    # Return an object describing the range of an empty loop at the given offset
    # in the given file, or None if no empty loop is found at that location.
    #
    # The range object is a struct object with two integer fields: begin_offset
    # and end_offset. Begin_offset is the offset of the first byte inside the
    # range, and end_offset is the offset of the first byte beyond the range.
    #
    @export
    def find_empty_loop(self, path, offset):
        _check_not_in_restricted_callback()
        #_tprint(f'find empty loop at {offset}')
        file_handle = self._get_file_handle(path)
        range = lib.ce_find_empty_loop(file_handle, offset)
        #_tprint(f"empty loop: {range}")
        _drop_file_handle(file_handle)
        if range.end_offset == 0:
            #_tprint(f"At {offset}: no empty loop found")
            return None
        return range

    # Callback called when the project status changes. Default does nothing.
    def report_project_status(self, status):
        pass

    # Callback called when the linker status changes. Default does nothing.
    def report_linker_status(self, status):
        pass

    # Callback called when the usage of an hdir changes. Used is true iff the
    # hdir is used. Default does nothing.
    def report_hdir_usage(self, path, used):
        pass

    # Callback when the inclusion status of a file in this project changes.
    # Default does nothing.
    def report_file_inclusion_status(self, file,  status):
        pass

    # Callback when the link status of a file in this project changes.
    # Default does nothing.
    def report_file_link_status(self, file,  status):
        pass

    # Callback when the analysis status of a file in this project changes.
    # Default does nothing.
    def report_file_analysis_status(self, file, status):
        pass

    # Callback when the UTF-8 status of a file in this project changes.
    # Default does nothing.
    def report_file_utf8_valid(self, file, valid):
        pass

    # Callback when the analysis progress of the project changes.
    # Default does nothing.
    #
    # Parameters:
    #  - "current": the number of files analyzed
    #  - "total": the total number of files to be analyzed
    #
    def report_progress(self, current, total):
        pass

    # Callback when a new target is found in the makefile. Default does nothing.
    #
    # Parameter:
    #  - "target": the name of the new target
    #
    def add_target(self, target):
        pass

    # Callback when a previously added target no longer exists in the
    # makefile. Default does nothing.
    #
    # Parameter:
    #  - "target": the name of the removed target
    #
    def remove_target(self, target):
        pass

    # Set diagnostic limit: the maximum number of diagnostics to be reported
    def set_diagnostic_limit(self, severity, limit):
        if lib is not None:
            severity = Severity(severity).value
            lib.ce_set_diagnostic_limit(self._handle, severity, limit)

    # Get diagnostic limit: the maximum number of diagnostics to be reported
    @export(fallback=0)
    def get_diagnostic_limit(self, severity):
        severity = Severity(severity).value
        return lib.ce_get_diagnostic_limit(self._handle, severity)

    # Callback from source analyzer to add a diagnostic. The source analyzer
    # assumes that initially, there are no diagnostics.  All changes are
    # reported using callbacks to add and remove diagnostics. This add
    # diagnostic callback should return a Python object (of any type) that
    # uniquely identifies the diagnostic. The call to remove the diagnostic will
    # get this object as a parameter. The default implementation does nothing.
    #
    # Diagnostics are ordered such that handling an earlier diagnostic has a
    # chance of also fixing a later diagnostic. 'after' is either a previously
    # added diagnostic or None. If it is a previously added diagnostic, then the
    # new diagnostic should be inserted after it.  If it is None, then the new
    # diagnostic should be first.
    def add_diagnostic(self, message, severity, category, file, offset, after):
        return None

    # Callback from source analyzer to remove a diagnostic previously added by
    # the add diagnostic callback. The parameter is the Python object returned
    # by the add diagnostic callback. The default implementation does nothing.
    def remove_diagnostic(self, diagnostic):
        pass

    # Callback from source analyzer to report the number of unreported
    # diagnostics.
    def report_more_diagnostics(self, severity, count):
        #print(f'{count} hidden {severity_name(severity)}s')
        pass

    def report_compilation_settings(self, file, compiler, flags):
        """Callback to report compilation settings extracted from makefile

        Called for source files - not header files - every time the compilation
        configuration for that file is successfully extracted.

        file -- the file object given when this file was added, or the path of
                the source file if no file object was given

        compiler -- the compiler path

        flags -- a list of strings representing user flags for the compiler
        """
        pass

    def set_memory_region(self,
                          name:str,
                          present:bool,
                          origin:int,
                          size:int,
                          attributes:str='',
    ) -> None:
        '''Callback to report memory regions as found in the linkerscript.

        Called whenever a new memory region is found, a memory region's origin
        or size change, or a memory region is removed. only the first time it is
        extracted and when the version changes.

        :param name:            The memory region's name.

        :param present:         True when the memory region is added or updated,
                                False when it is removed.

        :param origin:          Start address of the region; ignore if present
                                is False.

        :param size:            Size address of the region in bytes; ignore if
                                present is False.

        :param attributes:      Region attributes expressed in string format.
        '''
        #_eprint(f'set memory region {name} {present} {origin} {size}')
        pass

    def set_memory_section(self,
                          name:str,
                          present:bool,
                          runtime_region:str,
                          load_region:str,
    ) -> None:
        '''Callback to report memory regions as found in the linkerscript.

        Called whenever a new memory region is found, a memory region's origin
        or size change, or a memory region is removed. only the first time it is
        extracted and when the version changes.

        :param name:            The memory region's name.

        :param present:         True when the memory region is added or updated,
                                False when it is removed.

        :param runtime_region:  Name of region where this section resides at
                                runtime.

        :param load_region:     Name of region from where this section is
                                loaded.
        '''
        #_eprint(
        #    f'set memory section {name} {present}'
        #    f' {runtime_region} {load_region}'
        #)
        pass

    def report_internal_error(self, message):
        """Callback called when an internal error occurs in a background thread

        When this callback is called,  the source analyzer will no longer work
        and cannot recover.  It is advisable to save all edits and restart
        Embeetle.

        """
        print("SA FATAL: internal error - save changes and restart Embeetle")
        print(f"Details: {message}")
    
    # Callbacks below are internal (and their names start with an underscore)

    # Internal callback to create a Python object representing a symbol.  The
    # idea is to use this Python object in occurrence data sent to Python:
    # either in the return value from find_occurrence(...) or in a tracked
    # occurrence.  The C++ code will keep a reference to the Python object and
    # can re-use it until it calls _drop_symbol(...) below.
    #
    # The handle parameter is a pointer to a C++ object representing the symbol.
    # It can be used to get more information about the symbol, for example to
    # track occurrences of the symbol. It is guaranteed to be valid until a
    # matching _drop_symbol(...) call.
    #
    # Creates a Python Symbol object and adds it to the project's keep-alive set.
    def _add_symbol(self, name, kind, handle):
        symbol = Symbol(self, _decode(name), kind, handle)
        # C++ does not maintain Python reference counts. Keep a reference here
        # to make sure the symbol does not get garbage-collected before it is
        # used in Python.
        self._keep_alive.add(symbol)
        return symbol

    # Internal callback to drop the Python object representing a symbol. It is
    # called when there are no more tracked occurrences of this symbol *and* the
    # Python code has called _drop_entity_handle(...) for all occurrences of the
    # symbol returned by find_occurrence(...).
    #
    # After this call, the object will not be used in new occurrence data sent
    # to Python.  It may stay alive as long as there are still references to it
    # in Python data.
    def _drop_symbol(self, symbol):
        #_eprint(f"drop symbol: {symbol}")
        self._keep_alive.discard(symbol)

    # Private method to get the handle for an existing file with the given path.
    # Normalize the path, so that different paths referring to the same file
    # will return the same file.  Create the file if not found.
    def _get_file_handle(self, path):
        _check_not_in_restricted_callback()
        return lib.ce_get_file_handle(self._handle, _encode(path))

    # Private method to request re-extraction of all flags, for example because
    # the makefile changed. This will schedule the extraction of the flags in a
    # background thread.  If the new flags differ from the old flags, schedule a
    # re-analysis of the file. This function will return immediately: it will
    # not wait for the flag extraction or analysis to finish.
    def _request_flags_update(self):
        _check_not_in_restricted_callback()
        lib.ce_analyze_make_command(self._handle)

    # Private method to report a changed file analysis status.
    def _change_file_analysis_status(self, path, file, old_status, new_status):
        #_tprint(
        #    f"{analysis_status_name(old_status)} -> "
        #    f"{analysis_status_name(new_status)} for "
        #    f"{path} {file}"
        #)
        self.report_file_analysis_status(file or path, new_status)
        old_transient = (
            old_status is AnalysisStatus.WAITING
            or old_status is AnalysisStatus.BUSY
        )
        new_transient = (
            new_status is AnalysisStatus.WAITING
            or new_status is AnalysisStatus.BUSY
        )
        if old_transient != new_transient:
            if old_transient and not new_transient:
                #_eprint("inc progress for", path)
                self._progress_count += 1
                #self._busy_files.remove(path)
            else:
                #_eprint("inc progress total for", path)
                if not self._total_count:
                    self._start_analysis = _now()
                self._total_count += 1
                #self._busy_files.add(path)
            _tprint(
                f"progress {self._progress_count}/{self._total_count} {path}"
            )
            #_eprint(f"Busy files: {self._busy_files}")
            self.report_progress(self._progress_count, self._total_count)
            if self._progress_count == self._total_count:
                self._progress_count = 0
                self._total_count = 0

# Hdir status information, to populate the hdir status table.
# The status value is as reported by the source analyzer, ignoring mode.
# The status reported to the GUI takes the mode into account.
class Hdir:
    def __init__(self, user_data):
        self.mode = HdirMode.EXCLUDE
        self.status = InclusionStatus.EXCLUDED
        self.user_data = user_data
        
    def __str__(self):
        return (
            f'{hdir_mode_name(self.mode)} '
            f'{inclusion_status_name(self.status)}'
        )
                
# Symbol information, loaded once but currently not kept up-to-date.
#
# Basic data: project, name and kind, are set at creation time.  Occurrence data
# is represented by lists of locations, one per occurrence kind.  Location lists
# are loaded by calling _load_occurrence_lists(handle) and are not kept
# up-to-date.
#
# 
class Symbol:
    def __init__(self, project, name, kind, handle):
        # Add a reference to the symbol in the project's symbol set to avoid
        # garbage collection. There will be a reference to the symbol in the C++
        # code (as user data), but Python doesn't know that.
        #_eprint("init symbol")
        self.project = project
        self._name = name
        self._kind = kind
        self._occurrences_initialized = False
        self._definitions = []
        self._tentative_definitions = []
        self._weak_definitions = []
        self._declarations = []
        self._uses = []

    def __str__(self):
        return f'{self.kind_name} {self.name}'

    @property
    def name(self):
        return self._name
        
    @property
    def kind(self):
        return self._kind
        
    @property
    def kind_name(self):
        return symbol_kind_name(self.kind)
    
    # Lists of occurrences of different kinds for this symbol.  Each element of
    # the list consists of an object representing an occurrence.  It is
    # guaranteed to have the following four fields: `file` with the file object,
    # 'begin_offset' with the offset of the first character of the occurrence,
    # 'end_offset' with the offset of the first character beyond the occurrence,
    # and the 'linked' flag which is true iff this occurrence is linked into the
    # ELF file.
    #
    # It is expected that these lists will only be used for symbols found via
    # find_occurrence, and even then usually not, e.g. when called while
    # hovering over source code to determine what to highlight. For this reason,
    # the lists are only filled when requested by the application, e.g. to fill
    # a symbol information window.
    #
    # Currently, occurrences shown in a symbol information window are not
    # updated dynamically, so the lists reflect the situation at the last call
    # of find_occurrence.
    
    @property
    def definitions(self):
        assert self._occurrences_initialized
        return self._definitions
        
    @property
    def tentative_definitions(self):
        assert self._occurrences_initialized
        return self._tentative_definitions
        
    @property
    def weak_definitions(self):
        assert self._occurrences_initialized
        return self._weak_definitions
        
    @property
    def declarations(self):
        assert self._occurrences_initialized
        return self._declarations
    
    @property
    def uses(self):
        assert self._occurrences_initialized
        return self._uses

    # Update all occurrence lists.
    def _load_occurrence_lists(self, handle):
        self._occurrences_initialized = False
        self._definitions = []
        self._tentative_definitions = []
        self._weak_definitions = []
        self._declarations = []
        self._uses = []
        _track_occurrences_of_entity(handle, all_occurrence_kinds)
        self._occurrences_initialized = True
        _track_occurrences_of_entity(handle, [])

    # Get the list containing locations of the specified kind.
    def _list(self, kind):
        if kind in all_use_kinds:
            return self._uses
        if kind == occurrence_kind_definition:
            return self._definitions
        if kind in all_declaration_kinds:
            return self._declarations
        if kind == occurrence_kind_weak_definition:
            return self._weak_definitions
        if kind == occurrence_kind_tentative_definition:
            return self._tentative_definitions
        assert False, f'Unhandled kind {kind} {occurrence_kind_name(kind)}'

    # Tracking callback to add an occurrence
    def _add_occurrence(self, kind, occurrence):
        self._list(kind).append(occurrence)

# Location in source file as passed back to the application.
# All offsets are zero-based byte offsets.
class Location:
    def __init__(self, file, begin_offset, end_offset):
        class DummyFile:
            def __init__(self, path):
                self.path = path
            def __str__(self):
                return self.path
        self.file = DummyFile(file)
        self.begin_offset = begin_offset
        self.end_offset = end_offset
            
    def __str__(self):
        return f'{self.begin_offset}..{self.end_offset} in {self.file}'
    
class Occurrence(Location):
    def __init__(self, file, begin_offset, end_offset, kind, entity, linked):
        Location.__init__(self, file, begin_offset, end_offset)
        self.kind = kind
        self.entity = entity
        self.linked = linked
        
    def __str__(self):
        return f'{occurrence_kind_name(self.kind)} of {self.entity}' \
            f' at {Location.__str__(self)}'
    
# Create an object collecting occurrence data to be passed to the application.
# Collecting this data in a single object makes it more convenient to pass and
# makes it easier to change the set of data to be passed.
class FileOccurrence(Occurrence):
    def __init__(
            self, file, begin_offset, end_offset, kind, entity_handle, linked
    ) -> None:

        '''

        '''
        path = _get_file_path(entity_handle)
        Occurrence.__init__(
            self, file, begin_offset, end_offset, kind, path, linked
        )
        self.path = path

class SymbolOccurrence(Occurrence):
    def __init__(
            self, file, begin_offset, end_offset, kind, entity, linked
    ) -> None:
        '''

        '''
        symbol = _py_object(entity)
        Occurrence.__init__(
            self, file, begin_offset, end_offset, kind, symbol, linked
        )
        self.symbol = symbol

def user_occurrence(
        file, begin_offset, end_offset, kind, entity, entity_handle, linked
):
    if kind is occurrence_kind_include:
        # Entity is a file
        return FileOccurrence(
            file, begin_offset, end_offset, kind, entity_handle, linked
        )
    else:
        # Entity is a symbol
        return SymbolOccurrence(
            file, begin_offset, end_offset, kind, entity, linked
        )

def _create_project(
    project_path, cache_path, project, resource_path, lib_path
):
    @InclusionStatus_callback
    def set_inclusion_status(raw_path, user_data, status):
        _enter_restricted_callback("set_inclusion_status")
        try:
            path = _decode(raw_path)
            file = _py_object(user_data) or path
            project.report_file_inclusion_status(file, status)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_inclusion_status")
    project.report_inclusion_status_callback = set_inclusion_status

    @LinkStatus_callback
    def set_link_status(raw_path, user_data, status):
        _enter_restricted_callback("set_link_status")
        try:
            path = _decode(raw_path)
            file = _py_object(user_data) or path
            #_eprint(f"set_link_status {path}: {status}")
            project.report_file_link_status(file, status)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_link_status")
    project.report_link_status_callback = set_link_status

    @Utf8_callback
    def set_utf8_status(raw_path, user_data, status):
        _enter_restricted_callback("set_utf8_status")
        try:
            path = _decode(raw_path)
            file = _py_object(user_data) or path
            #_eprint(f"set_utf8_status {path}: {status}")
            project.report_file_utf8_valid(file, status)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_utf8_status")
    project.set_utf8_status_callback = set_utf8_status

    @AnalysisStatus_callback
    def change_analysis_status(raw_path, user_data, old_status, new_status):
        #_eprint(f"analysis status {raw_path} {old_status} -> {new_status}")
        _enter_restricted_callback("set_analysis_status")
        try:
            old_status = AnalysisStatus(old_status)
            new_status = AnalysisStatus(new_status)
            path = _decode(raw_path)
            file = _py_object(user_data) or path
            if trace:
                _eprint(f"change_analysis_status {path}"
                        f" from {analysis_status_name(old_status)}"
                        f" to {analysis_status_name(new_status)}"
                )
            project._change_file_analysis_status(
                path, file, old_status, new_status
            )
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_analysis_status")
    project._change_analysis_status_callback = change_analysis_status

    @AddSymbol_callback
    def add_symbol(name, kind, handle):
        return id(project._add_symbol(name, kind, handle))
    project._add_symbol_callback = add_symbol
        
    @DropSymbol_callback
    def drop_symbol(symbol):
        project._drop_symbol(_py_object(symbol))
    project._drop_symbol_callback = drop_symbol
        
    @ProjectStatus_callback
    def set_project_status(handle, status):
        _enter_restricted_callback("set_project_status")
        try:
            status = ProjectStatus(status)
            #_tprint(f'project status -> {project_status_name(status)}')
            if trace:
                _eprint(f"Report project status {project_status_name(status)}")
            project.report_project_status(status)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_project_status")
    project._set_project_status_callback = set_project_status

    @LinkerStatus_callback
    def set_linker_status(handle, status):
        _enter_restricted_callback("set_linker_status")
        try:
            status = LinkerStatus(status)
            if trace:
                _eprint(f"Report linker status {linker_status_name(status)}")
            project.report_linker_status(status)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_linker_status")
    project._set_linker_status_callback = set_linker_status

    @HdirUsage_callback
    def set_hdir_usage(raw_path, status):
        _enter_restricted_callback("set_hdir_usage")
        try:
            path = _decode(raw_path)
            if trace:
                _eprint(f"set_hdir_usage {path} = "
                        f"{inclusion_status_name(status)}"
                )
            project._set_hdir_usage(path, InclusionStatus(status))
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_hdir_usage")
    project._set_hdir_usage_callback = set_hdir_usage
    
    @AddDiagnostic_callback
    def add_diagnostic(
            message, severity, category, raw_path, user_data, offset, after
    ):
        _enter_restricted_callback('add_diagnostic')
        try:
            path = _decode(raw_path) if raw_path else None
            file = _py_object(user_data) or path
            severity = Severity(severity)
            category = Category(category)
            if trace:
                _eprint(f'Add diagnostic in {path}: {message}')
            after = _py_object(after)
            diagnostic = project.add_diagnostic(
                _decode(message), severity, category, file, offset, after
            )
            # Keep a reference to the returned object to avoid garbage
            # collection. Ctypes doesn't handle this case automatically.
            if diagnostic:
                assert(diagnostic not in project.diagnostic_set)
                project.diagnostic_set.add(diagnostic)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("add_diagnostic")
        return id(diagnostic)
    project._add_diagnostic_callback = add_diagnostic
        
    @RemoveDiagnostic_callback
    def remove_diagnostic(diagnostic):
        _enter_restricted_callback("remove_diagnostic")
        try:
            if trace:
                _eprint(f'remove diagnostic {diagnostic}')
            #
            # Remove the reference to the diagnostic's Python object to allow
            # garbage collection.
            if diagnostic:
                assert diagnostic in project.diagnostic_set
                project.diagnostic_set.remove(diagnostic)
            project.remove_diagnostic(diagnostic)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("remove_diagnostic")
    project._remove_diagnostic_callback = remove_diagnostic

    @MoreDiagnostics_callback
    def more_diagnostics(handle, severity, count):
        _enter_restricted_callback('more_diagnostics')
        try:
            severity = Severity(severity)
            if trace:
                _eprint(f'more diagnostics {severity} {count}')
            project.report_more_diagnostics(severity, count)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("more_diagnostics")
    project._more_diagnostics_callback = more_diagnostics
        
    @AddOccurrenceInFile_callback
    def add_occurrence_in_file(
        path, begin_offset, end_offset, kind, entity, entity_handle, scope,
        linked
    ):
        _enter_restricted_callback("add_occurrence_in_file")
        try:
            data = user_occurrence(
                _decode(path), begin_offset, end_offset,
                kind, entity, entity_handle, linked
            )
            occurrence = project.add_occurrence(data, _py_object(scope))
            if trace:
                _eprint(
                    f'add tracked {occurrence_kind_name(kind)} of '
                    f'{data.entity}'
                    f' at {begin_offset} in {_py_object(scope)}'
                    f' --> {occurrence} linked={linked}'
                )
            # Keep a reference to the returned object to avoid garbage
            # collection. Ctypes doesn't handle this case automatically.
            if occurrence:
                assert occurrence not in project.occurrence_set
                project.occurrence_set.add(occurrence)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("add_occurrence_in_file")
        return id(occurrence)
    project._add_occurrence_in_file_callback = add_occurrence_in_file
    
    @RemoveOccurrenceInFile_callback
    def remove_occurrence_in_file(occurrence):
        _enter_restricted_callback("remove_occurrence_in_file")
        try:
            if trace:
                _eprint(f'remove tracked occurrence {occurrence}')
            if occurrence:
                assert occurrence in project.occurrence_set
                project.occurrence_set.remove(occurrence)
            project.remove_occurrence(occurrence)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("remove_occurrence_in_file")
    project._remove_occurrence_in_file_callback = remove_occurrence_in_file
    
    @OccurrencesInFileCount_callback
    def occurrences_in_file_count(count):
        _enter_restricted_callback("occurrences_in_file_count")
        try:
            if trace:
                _eprint(f'set tracked occurrences in file count {count}')
            project.report_occurrences_count(count)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("occurrences_in_file_count")
    project._occurrences_in_file_count_callback = occurrences_in_file_count
    
    @SetAlternativeContent_callback
    def set_alternative_content(raw_path, file_user_data, content):
        _enter_restricted_callback("set_alternative_content")
        try:
            path = _decode(raw_path)
            if trace:
                _eprint(f'set_alternative_content {path} {content[:30]}')
            file = _py_object(file_user_data) or path
            project.set_alternative_content(file, _decode(content))
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_alternative_content")
    project._set_alternative_content_callback = set_alternative_content
    
    @AddOccurrenceOfEntity_callback
    def add_occurrence_of_entity(
        path, begin_offset, end_offset, kind, raw_entity, entity_handle, linked
    ):
        _enter_restricted_callback("add_occurrence_of_entity")
        try:
            entity = _py_object(raw_entity)
            occurrence = Occurrence(
                _decode(path), begin_offset, end_offset, kind, entity, linked
            )
            if kind == occurrence_kind_include:
                # Add include of file
                includes = project.tracked_file_includes.get(entity_handle)
                if not includes:
                    project.tracked_file_includes[entity_handle] = []
                    includes = project.tracked_file_includes.get(entity_handle)
                includes.append(occurrence)
            else:
                # Add occurrence of symbol
                assert entity
                entity._add_occurrence(kind, occurrence)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("add_occurrence_of_entity")
        # No need to return anything: we don't dynamically update entity
        # occurrence lists (yet).
        return id(occurrence)
    project._add_occurrence_of_entity_callback = add_occurrence_of_entity
    
    @RemoveOccurrenceOfEntity_callback
    def remove_occurrence_of_entity(location):
        _enter_restricted_callback("remove_occurrence_of_entity")
        try:
            # Do nothing; we don't dynamically update entity occurrence lists
            # (yet).
            pass
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("remove_occurrence_of_entity")
    project._remove_occurrence_of_entity_callback = remove_occurrence_of_entity

    @OccurrencesOfEntityCount_callback
    def occurrences_of_entity_count(count):
        _enter_restricted_callback("occurrences_of_entity_count")
        try:
            if trace:
                _eprint(f'set tracked occurrences of entity count {count}')
            project.report_occurrences_of_entity_count(count)
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("occurrences_of_entity_count")
    project._occurrences_of_entity_count_callback = occurrences_of_entity_count
    
    @SetOccurrenceOfEntityLinked_callback
    def set_occurrence_of_entity_linked(location, linked):
        _enter_restricted_callback("set_occurrence_of_entity_linked")
        try:
            # Do nothing; we don't dynamically update entity occurrence lists
            # (yet).
            pass
        except Exception as error:
            project.report_internal_error(traceback.format_exc())
            raise error
        finally:
            _leave_restricted_callback("set_occurrence_of_entity_linked")
    project._set_occurrence_of_entity_linked_callback = \
      set_occurrence_of_entity_linked

    @ReportInternalError_callback
    def report_internal_error(message, handle):
        _eprint(f"Report internal error (thread {threading.get_ident()})")
        project.report_internal_error(_decode(message))
    project._report_internal_error_callback = report_internal_error
    
    @SetMemoryRegion_callback
    def set_memory_region(name, present, origin, size):
        #_eprint(f"Set memory region {name} {present} {origin} {size}")
        project.set_memory_region(_decode(name), present, origin, size)
    project._set_memory_region_callback = set_memory_region
    
    @SetMemorySection_callback
    def set_memory_section(name, present, runtime_region, load_region):
        #_eprint(
        #  f'Set memory section {name} {present} {runtime_region} {load_region}'
        # )
        project.set_memory_section(
            _decode(name), present,
            _decode(runtime_region),
            _decode(load_region)
        )
    project._set_memory_section_callback = set_memory_section
    
    #_eprint("create project")
    return lib.ce_create_project(
        project_path.encode("utf-8"),
        cache_path.encode("utf-8"),
        resource_path.encode("utf-8"),
        lib_path.encode("utf-8"),
        set_project_status,
        set_inclusion_status,
        set_link_status,
        change_analysis_status,
        add_symbol,
        drop_symbol,
        set_linker_status,
        set_hdir_usage,
        add_diagnostic,
        remove_diagnostic,
        more_diagnostics,
        add_occurrence_in_file,
        remove_occurrence_in_file,
        occurrences_in_file_count,
        set_alternative_content,
        add_occurrence_of_entity,
        remove_occurrence_of_entity,
        occurrences_of_entity_count,
        set_occurrence_of_entity_linked,
        report_internal_error,
        set_memory_region,
        set_memory_section,
        set_utf8_status,
        project,
    )

def _set_toolchain_prefix(project_handle, prefix):
    _check_not_in_restricted_callback()
    lib.ce_set_toolchain_prefix(project_handle, _encode(prefix))

def _set_make_command(project_handle, command, env):
    _check_not_in_restricted_callback()
    command_buffer = _encode_list(command)
    lib.ce_set_make_command(project_handle, command_buffer, len(command_buffer))

def _set_build_path(project_handle, path):
    _check_not_in_restricted_callback()
    lib.ce_set_build_path(project_handle, path.encode("utf-8"))

def _drop_file_handle(file_handle):
    _check_not_in_restricted_callback()
    lib.ce_drop_file_handle(file_handle)

def _drop_entity_handle(entity_handle):
    _check_not_in_restricted_callback()
    lib.ce_drop_entity_handle(entity_handle)

def _reload_file(file_handle):
    _check_not_in_restricted_callback()
    lib.ce_reload_file(file_handle)

def _get_file_project(file_handle):
    return lib.ce_get_file_project(file_handle)
    
def _get_file_path(file_handle):
    return _decode(lib.ce_get_file_path(file_handle))
    
def _add_file(file_handle, mode, file_python_obj):
    _check_not_in_restricted_callback()
    lib.ce_add_file(file_handle, mode.value, file_python_obj)

def _set_file_mode(file_handle, mode):
    _check_not_in_restricted_callback()
    lib.ce_set_file_mode(file_handle, mode.value)

def _remove_file(file_handle):
    _check_not_in_restricted_callback()
    lib.ce_remove_file(file_handle)

def _get_file_mode(file_handle):
    return FileMode(lib.ce_get_file_mode(file_handle))

def _get_file_kind(file_handle):
    return FileKind(lib.ce_get_file_kind(file_handle))

def _get_file_user_data(file_handle):
    return _py_object(lib.ce_get_file_user_data(file_handle))

def _file_analysis_data_was_read_from_cache(file_handle):
    return lib.ce_analysis_data_was_read_from_cache(file_handle)

def _track_occurrences_of_entity(entity_handle, occurrence_kinds):
    _check_not_in_restricted_callback()
    lib.ce_track_occurrences_of_entity(
        entity_handle,
        _list_to_bitset(occurrence_kinds),
    )

def _list_to_bitset(list):
    bitset = 0
    for value in list:
        bitset |= (1 << value)
    return bitset

def _edit_file(file_handle, begin_offset, end_offset, new_content):
    _check_not_in_restricted_callback()
    lib.ce_edit_file(file_handle, begin_offset, end_offset,_encode(new_content))

nr_of_workers = 0
def set_number_of_workers(n):
    global nr_of_workers
    nr_of_workers = n
    lib.ce_set_number_of_workers(n)

def get_number_of_workers():
    return nr_of_workers

def start():
    if trace:
        _eprint(">>> START ENGINE")
    lib.ce_start()

def stop():
    if trace:
        _eprint(">>> STOP ENGINE")
    lib.ce_stop()

def abort():
    if lib:
        lib.ce_abort()

# Occurrence data coming from C++
#
# The entity and file fields are not declared as py_object but as c_void_p
# because they can be null (when no occurrence is found) and the ctypes library
# complains with 'ValueError: PyObject is NULL' when attempting to convert a
# null pointer to a python object.
class OccurrenceData(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_int),                # entity kind
        ("entity", ctypes.c_void_p),           # entity user data
        ("entity_handle", ctypes.c_void_p),    # entity handle
        ("path", ctypes.c_char_p),             # file path
        ("begin_offset", ctypes.c_uint),       # zero based byte offset
        ("end_offset", ctypes.c_uint),         # zero based byte offset
        ("linked", ctypes.c_bool),             # linked
    ]

# Range data coming from C++
class RangeData(ctypes.Structure):
    _fields_ = [
        ("begin_offset", ctypes.c_uint),       # zero based byte offset
        ("end_offset", ctypes.c_uint),         # zero based byte offset
    ]

    def __str__(self):
        return f'{self.begin_offset}..{self.end_offset}'
    

lib = None

def init(so_path, debug_print=print, debug=False):

    global _debug_print
    _debug_print = debug_print if debug else None
    
    #_eprint(f"so path: {so_path}")
    global lib
    if lib:
        return
    
    # If loading of the SO fails with a segmentation fault, check that all
    # symbols in the SO are defined (use make linktest)!
    #
    # Use cdll instead of `lib = ctypes.PyDLL(so)` below, to avoid keeping the
    # GIL locked while C code is running.
    lib = ctypes.cdll.LoadLibrary(so_path)
    #lib = ctypes.PyDLL(so_path)

    # Uncomment to run quick test with SO initialized
    #_quick_test()
    
    lib.ce_project_status_name.restype = ctypes.c_char_p
    lib.ce_project_status_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_linker_status_name.restype = ctypes.c_char_p
    lib.ce_linker_status_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_file_mode_name.restype = ctypes.c_char_p
    lib.ce_file_mode_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_file_kind_name.restype = ctypes.c_char_p
    lib.ce_file_kind_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_inclusion_status_name.restype = ctypes.c_char_p
    lib.ce_inclusion_status_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_analysis_status_name.restype = ctypes.c_char_p
    lib.ce_analysis_status_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_entity_kind_name.restype = ctypes.c_char_p
    lib.ce_entity_kind_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_occurrence_kind_name.restype = ctypes.c_char_p
    lib.ce_occurrence_kind_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_link_status_name.restype = ctypes.c_char_p
    lib.ce_link_status_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_severity_name.restype = ctypes.c_char_p
    lib.ce_severity_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_category_name.restype = ctypes.c_char_p
    lib.ce_category_name.argtypes = [ ctypes.c_int ]
    
    lib.ce_create_project.restype = ctypes.c_void_p # project handle
    lib.ce_create_project.argtypes = [
        ctypes.c_char_p,     # project path
        ctypes.c_char_p,     # cache path
        ctypes.c_char_p,     # resource path
        ctypes.c_char_p,     # lib path
        ProjectStatus_callback,
        InclusionStatus_callback,
        LinkStatus_callback,
        AnalysisStatus_callback,
        AddSymbol_callback,
        DropSymbol_callback,
        LinkerStatus_callback,
        HdirUsage_callback,
        AddDiagnostic_callback,
        RemoveDiagnostic_callback,
        MoreDiagnostics_callback,
        AddOccurrenceInFile_callback,
        RemoveOccurrenceInFile_callback,
        OccurrencesInFileCount_callback,
        SetAlternativeContent_callback,
        AddOccurrenceOfEntity_callback,
        RemoveOccurrenceOfEntity_callback,
        OccurrencesOfEntityCount_callback,
        SetOccurrenceOfEntityLinked_callback,
        ReportInternalError_callback,
        SetMemoryRegion_callback,
        SetMemorySection_callback,
        Utf8_callback,
        ctypes.py_object,    # user data
    ]
    
    lib.ce_drop_project.restype = None # void
    lib.ce_drop_project.argtypes = [
        ctypes.c_void_p,     # project handle
    ]

    lib.ce_set_toolchain_prefix.restype = None # void
    lib.ce_set_toolchain_prefix.argtypes = [
        ctypes.c_void_p,     # project handle 
        ctypes.c_char_p,     # log file path
    ]
    
    lib.ce_set_build_path.restype = None # void
    lib.ce_set_build_path.argtypes = [
        ctypes.c_void_p,     # project handle 
        ctypes.c_char_p,     # log file path
    ]
    
    lib.ce_add_hdir.restype = None # void
    lib.ce_add_hdir.argtypes = [
        ctypes.c_void_p,     # project handle 
        ctypes.c_char_p,     # hdir path
    ]
    
    lib.ce_remove_hdir.restype = None # void
    lib.ce_remove_hdir.argtypes = [
        ctypes.c_void_p,     # project handle 
        ctypes.c_char_p,     # hdir path
    ]

    lib.ce_get_file_handle.restype = ctypes.c_void_p # file handle
    lib.ce_get_file_handle.argtypes = [
        ctypes.c_void_p,     # project handle 
        ctypes.c_char_p,     # file path
    ]
    
    lib.ce_drop_file_handle.restype = None # void
    lib.ce_drop_file_handle.argtypes = [
        ctypes.c_void_p,     # file handle
    ]

    lib.ce_get_file_project.restype = ctypes.c_void_p # project handle
    lib.ce_get_file_project.argtypes = [
        ctypes.c_void_p,     # file handle
    ]

    lib.ce_get_file_path.restype = ctypes.c_char_p # source file path
    lib.ce_get_file_path.argtypes = [
        ctypes.c_void_p,     # file handle
    ]
    
    lib.ce_get_file_mode.restype = ctypes.c_int 
    lib.ce_get_file_mode.argtypes = [
        ctypes.c_void_p,     # file handle
    ]
    
    lib.ce_get_file_kind.restype = ctypes.c_int 
    lib.ce_get_file_kind.argtypes = [
        ctypes.c_void_p,     # file handle
    ]
    
    lib.ce_get_file_user_data.restype = ctypes.c_void_p # user data can be null
    lib.ce_get_file_user_data.argtypes = [
        ctypes.c_void_p,     # file handle
    ]
    
    lib.ce_analysis_data_was_read_from_cache.restype = ctypes.c_bool
    lib.ce_analysis_data_was_read_from_cache.argtypes = [
        ctypes.c_void_p,     # file handle
    ]
    
    lib.ce_add_file.restype = None # void
    lib.ce_add_file.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_int,        # mode
        ctypes.py_object,    # user data
    ]

    lib.ce_set_file_mode.restype = None # void
    lib.ce_set_file_mode.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_int,        # mode
    ]

    lib.ce_remove_file.restype = None # void
    lib.ce_remove_file.argtypes = [
        ctypes.c_void_p,     # file handle
    ]

    lib.ce_track_occurrences_in_file.restype = None # void
    lib.ce_track_occurrences_in_file.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_uint,       # occurrence kinds
        ctypes.c_uint,       # entity kinds
    ]
    
    lib.ce_track_occurrences_of_entity.restype = None # void
    lib.ce_track_occurrences_of_entity.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_uint,       # occurrence kinds
    ]
    
    lib.ce_set_make_command.restype = None # void
    lib.ce_set_make_command.argtypes = [
        ctypes.c_void_p,     # project handle
        ctypes.c_char_p,     # command buffer
        ctypes.c_uint,       # command buffer size
    ]
    
    lib.ce_analyze_make_command.restype = None # void
    lib.ce_analyze_make_command.argtypes = [
        ctypes.c_void_p,     # project handle
    ]
    
    lib.ce_edit_file.restype = None # void
    lib.ce_edit_file.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_uint,       # zero based byte offset of first changed byte
        ctypes.c_uint,       # zero based byte offset of first unchanged byte
        ctypes.c_char_p,     # new content of changed range
    ]
    
    lib.ce_reload_file.restype = None # void
    lib.ce_reload_file.argtypes = [
        ctypes.c_void_p,     # file handle
    ]
    
    lib.ce_find_occurrence.restype = OccurrenceData
    lib.ce_find_occurrence.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_uint,       # offset
        ctypes.c_uint,       # begin-tolerance
        ctypes.c_uint,       # end-tolerance
    ]

    lib.ce_find_symbols.restype = None
    lib.ce_find_symbols.argtypes = [
        ctypes.c_void_p,     # project handle
        ctypes.c_char_p,     # name
        FindSymbol_callback,
        ctypes.c_void_p,     # callback user data
    ]

    lib.ce_get_completions.restype = ctypes.c_uint # insertion byte offset
    lib.ce_get_completions.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_uint,       # completion position byte offset
        AddCompletion_callback,
        ctypes.c_void_p,     # callback user data
        ctypes.c_char_p,     # context upto insertion position
    ]

    lib.ce_find_empty_loop.restype = RangeData
    lib.ce_find_empty_loop.argtypes = [
        ctypes.c_void_p,     # file handle
        ctypes.c_uint,       # offset
    ]

    lib.ce_drop_entity_handle.restype = None
    lib.ce_drop_entity_handle.argtypes = [
        ctypes.c_void_p,     # entity handle
    ]

    lib.ce_set_number_of_workers.restype = None
    lib.ce_set_number_of_workers.argtypes = [
        ctypes.c_uint,       # new number of workers
    ]

    lib.ce_start.restype = None
    lib.ce_start.argtypes = []

    lib.ce_stop.restype = None
    lib.ce_stop.argtypes = []

    lib.ce_abort.restype = None
    lib.ce_abort.argtypes = []

    lib.ce_set_diagnostic_limit.restype = None # void
    lib.ce_set_diagnostic_limit.argtypes = [
        ctypes.c_void_p,     # project handle
        ctypes.c_uint,       # severity
        ctypes.c_uint,       # limit
    ]

    lib.ce_check.restype = None
    lib.ce_check.argtypes = [
        ctypes.c_void_p,     # pointer to check
    ]

    #print_all_entity_kinds()
    
# Type of function called when the project status changes
ProjectStatus_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_void_p,         # project handle
    ctypes.c_int,            # project status
)

# Type of function called to create user data for a symbol
AddSymbol_callback = ctypes.CFUNCTYPE(
    ctypes.c_void_p,         # returned user data
    ctypes.c_char_p,         # symbol name
    ctypes.c_int,            # symbol kind (an entity kind)
    ctypes.c_void_p,         # symbol handle
)

# Type of function called to drop a symbol
DropSymbol_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_void_p,         # symbol user data
)

# Type of function called when the linker status of a project changes
LinkerStatus_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_void_p,         # project handle
    ctypes.c_int,            # link status
)

# Type of function called when the usage of an hdir changes
HdirUsage_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # path
    ctypes.c_int,            # usage status: an inclusion status code
)

# Type of function called when a file's inclusion status changes.
InclusionStatus_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # file path
    ctypes.c_void_p,         # file user data
    ctypes.c_uint,           # status
)

# Type of function called when a file's link status changes.
LinkStatus_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # file path
    ctypes.c_void_p,         # file user data
    ctypes.c_uint,           # status
)

# Type of function called when the analysis status of a file changes
AnalysisStatus_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # file path
    ctypes.c_void_p,         # file user data
    ctypes.c_int,            # old status
    ctypes.c_int,            # new status
)

AddDiagnostic_callback = ctypes.CFUNCTYPE(
    ctypes.c_void_p,         # returned user data
    ctypes.c_char_p,         # message
    ctypes.c_int,            # severity
    ctypes.c_int,            # category
    ctypes.c_char_p,         # path of file containing the diagnostic
    ctypes.c_void_p,         # file user data or null
    ctypes.c_uint,           # zero based byte offset
    ctypes.c_void_p,         # previous diagnostic, or null for first
)

RemoveDiagnostic_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.py_object,        # diagnostic user data
)

MoreDiagnostics_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_void_p,         # project handle
    ctypes.c_int,            # severity
    ctypes.c_uint,           # number of hidden diagnostics
)

AddOccurrenceInFile_callback = ctypes.CFUNCTYPE(
    ctypes.c_void_p,         # returned occurrence user data
    ctypes.c_char_p,         # file path
    ctypes.c_uint,           # zero based begin byte offset
    ctypes.c_uint,           # zero based end byte offset
    ctypes.c_int,            # occurrence kind
    ctypes.c_void_p,         # entity user data (can be null)
    ctypes.c_void_p,         # entity handle
    ctypes.c_void_p,         # scope user data or null
    ctypes.c_bool,           # linked
)

RemoveOccurrenceInFile_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.py_object,        # occurrence user data
)

OccurrencesInFileCount_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_uint,           # count
)

SetAlternativeContent_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # file path
    ctypes.c_void_p,         # file user data
    ctypes.c_char_p,         # file content
)

AddOccurrenceOfEntity_callback = ctypes.CFUNCTYPE(
    ctypes.c_void_p,         # returned occurrence user data
    ctypes.c_char_p,         # file path
    ctypes.c_uint,           # zero based begin byte offset
    ctypes.c_uint,           # zero based end byte offset
    ctypes.c_int,            # occurrence kind
    ctypes.c_void_p,         # entity user data
    ctypes.c_void_p,         # entity handle
    ctypes.c_bool,           # linked
)

RemoveOccurrenceOfEntity_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.py_object,        # occurrence user data
)

OccurrencesOfEntityCount_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_uint,           # count
)

SetOccurrenceOfEntityLinked_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.py_object,        # occurrence user data
    ctypes.c_bool,           # linked
)

SetMemoryRegion_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # region name
    ctypes.c_bool,           # present
    ctypes.c_uint,           # origin 
    ctypes.c_uint,           # size
)

SetMemorySection_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # section name
    ctypes.c_bool,           # present
    ctypes.c_char_p,         # runtime memory region name
    ctypes.c_char_p,         # load memory region name
)

ReportInternalError_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # message
    ctypes.c_void_p,         # project user data
)

FindSymbol_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_void_p,         # symbol user data (can be null)
    ctypes.c_void_p,         # symbol handle
    ctypes.c_void_p,         # user data
)

AddCompletion_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # completion
    ctypes.c_void_p,         # user data
)

# Type of function called when a file's UTF-8 status changes.
Utf8_callback = ctypes.CFUNCTYPE(
    None,                    # no return value
    ctypes.c_char_p,         # file path
    ctypes.c_void_p,         # file user data
    ctypes.c_bool,           # true iff is valid UTF-8
)

def _decode(c_string):
    return c_string.decode('utf-8')

def _encode(string):
    return string.encode('utf-8')

def _encode_list(string_list):
    return _encode('\0'.join(string_list))

def _py_object(ud):
    return ctypes.cast(ud, ctypes.py_object).value if ud else None

# Test code,  intended for experiments with dll, ctypes and gc.
# To run,  uncomment call in init(...) and test function in source_analyzer.cpp
def _quick_test():
    _eprint("Hello")
    CreateCallback = ctypes.CFUNCTYPE( ctypes.c_void_p )
    DestroyCallback = ctypes.CFUNCTYPE( None, ctypes.c_void_p )
    lib.test.restype = None
    lib.test.argtypes = [ CreateCallback, DestroyCallback ]

    class Foo:
        def __init__(self, n):
            self.n = n
            _tprint(f"create Foo {self.n} {hex(id(self))}")
            
        def __del__(self):
            _tprint(f"garbage collect Foo {self.n} {hex(id(self))}");

    n = 0
    while True:
        n = n + 1

        @CreateCallback
        def create():
            return id(Foo(n))
        
        @DestroyCallback
        def destroy(object):
            foo = _py_object(object)
            _tprint(f"destroy Foo {foo.n} {hex(id(foo))}")
            pass

        lib.test(create, destroy)
    _eprint("Bye")
    sys.exit(1)
