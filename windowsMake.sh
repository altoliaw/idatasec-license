#!/bin/bash
# Dependency porcess
# Traversal of globalDependencies.json
Vendors="Vendors"
source $(pwd)/Shells/installVendor.sh && \
dependenciesTraversal $(pwd)/Settings/.Json/globalDependencies.json $(pwd)/$Vendors/.$Vendors.json

# Cmake process
rm -rf build
mkdir -p build
cmake -S . -B build -DBUILD_TEST=OFF
cmake --build build
cd build
cp -ar ./Apps/SizingMain_Windows.exe ../Bin/
cd ..