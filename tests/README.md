# Injection classifier regression tests

The regression corpus contains 100 deterministic samples with manually assigned labels:

- 25 normal hotpatch samples (classic hotpatch slot, same-module entry detour, copied-prologue trampoline)
- 25 code cave samples (padding overwrite, expanded section, jump into unused code)
- 25 shellcode jump samples (external/private target, suspicious target module, thread flow outside named modules)
- 25 module replacement samples, including non-replacement header-change counterexamples

Build and run the test directly on any platform with a C++11 compiler:

```console
g++ -std=c++11 -Iscanners tests/injection_classifier_test.cpp scanners/injection_classifier.cpp -o /tmp/injection_classifier_test
/tmp/injection_classifier_test
```

With CMake, configure with `-DPESIEVE_BUILD_TESTING=ON` and run `ctest`.
