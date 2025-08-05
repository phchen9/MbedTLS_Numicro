# MbedTLS_Numicro

## Get Started

### Requirement

* Nuvoton M2354
* Toolchain: `CMake`, `Ninja` and `Arm Compiler 6`

### Cloning the Repository

```
https://github.com/phchen9/MbedTLS_Numicro.git --recurse-submodules
```

### Patching the Repository

```
cd lib/mbedtlslib/mbedtls
patch -p1 < ../patches/*.patch
```

### Build

```
mkdir build
cmake -B build --preset default
cmake --build ./build
```
