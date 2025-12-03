import sys
import os
import shutil
import tempfile
import datetime
from datetime import datetime as dt

# Add source directories to python path
repo_root = os.getcwd()
sys.path.append(os.path.join(repo_root, 'MLForensics-farzana', 'FAME-ML'))
sys.path.append(os.path.join(repo_root, 'MLForensics-farzana', 'mining'))
sys.path.append(os.path.join(repo_root, 'MLForensics-farzana', 'empirical'))

try:
    import mining
    import py_parser
    import lint_engine
    import report
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

def fuzz_method(method_name, method_obj, input_sets):
    """
    Generic fuzzer that takes a method and a list of argument tuples.
    input_sets should be a list of tuples, e.g. [(arg1,), (arg1, arg2)]
    """
    print(f"--- Fuzzing {method_name} ---")
    for args in input_sets:
        try:
            # We unpack the arguments *args into the method
            method_obj(*args)
        except Exception as e:
            # We catch ALL exceptions to ensure the fuzzer keeps running
            print(f"[BUG/CRASH FOUND] Method '{method_name}' failed.")
            print(f"  Inputs: {args}")
            print(f"  Exception: {type(e).__name__}: {e}")
    print(f"--- End Fuzzing {method_name} ---\n")

def main():
    # --- Setup Temporary Test Files ---
    # We create real files/dirs to test logic that passes os.path.exists checks
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, "temp_test.py")
    with open(temp_file, "w") as f:
        f.write("import os\nprint('hello')")
    
    empty_file = os.path.join(temp_dir, "empty.py")
    with open(empty_file, "w") as f:
        f.write("")

    non_py_file = os.path.join(temp_dir, "text.txt")
    with open(non_py_file, "w") as f:
        f.write("Just text")

    # --- 1. Define Input Sets by Category ---

    # A. Generic Garbage (for any argument)
    garbage = [None, 12345, 0.0, "random_string", [], {}, object()]

    # B. Date Inputs (for mining.days_between)
    # Includes: valid dates, strings, ints, mixed types
    now = dt.now()
    date_inputs = [
        (now, now),                               # Valid
        (now, "2025-01-01"),                      # Type Mismatch (Date, Str)
        ("2020-01-01", now),                      # Type Mismatch (Str, Date)
        (None, now),                              # None check
        (123, 456),                               # Ints
        (now, None)
    ]

    # C. Path Inputs (for file system methods)
    # Includes: valid paths, invalid paths, wrong types
    path_inputs = [
        (temp_dir,),                              # Valid Directory
        (temp_file,),                             # Valid File
        (non_py_file,),                           # Valid non-python file
        (empty_file,),                            # Empty file
        ("non_existent_file.py",),                # Path that doesn't exist
        (None,),                                  # None
        (12345,),                                 # Int
        ([],),                                    # List
        (b'bytes_path',)                          # Bytes
    ]

    # D. List Inputs (for statistical methods)
    # Includes: valid lists, empty lists, mixed types
    list_inputs = [
        ([1, 2, 3, 4, 5],),                       # Valid List
        ([],),                                    # Empty List (ZeroDivision risk)
        ([1, "two", 3],),                         # Mixed types (TypeError risk in sum)
        (None,),                                  # None
        (12345,),                                 # Not a list
        ("string_as_list",)                       # Iterable but not numbers
    ]

    try:
        # --- 2. Execute Fuzzing ---

        # Method 1: mining.days_between (Expects 2 datetime objects)
        # Vulnerabilities: AttributeError (if input lacks .days), TypeError
        fuzz_method("mining.days_between", mining.days_between, date_inputs)

        # Method 2: mining.getPythonFileCount (Expects directory path string)
        # Vulnerabilities: TypeError in os.walk if not string/bytes
        fuzz_method("mining.getPythonFileCount", mining.getPythonFileCount, path_inputs)

        # Method 3: py_parser.checkIfParsablePython (Expects file path string)
        # Vulnerabilities: FileNotFoundError, IsADirectoryError, TypeError on open()
        fuzz_method("py_parser.checkIfParsablePython", py_parser.checkIfParsablePython, path_inputs)

        # Method 4: lint_engine.getDataLoadCount (Expects file path string)
        # Vulnerabilities: Dependent on py_parser success, AST parsing errors
        fuzz_method("lint_engine.getDataLoadCount", lint_engine.getDataLoadCount, path_inputs)

        # Method 5: report.Average (Expects list of numbers)
        # Vulnerabilities: ZeroDivisionError, TypeError
        fuzz_method("report.Average", report.Average, list_inputs)

    finally:
        # --- Cleanup ---
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
