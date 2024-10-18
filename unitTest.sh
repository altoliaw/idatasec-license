#!/bin/bash
# "-c" implies that the vendor shall be verified.
# Dependency porcess
# Traversal of globalDependencies.json
if [[ "$1" == "-c" ]]; then
	Vendors="Vendors"
	source $(pwd)/Shells/installVendor.sh && \
	dependenciesTraversal $(pwd)/Settings/.Json/globalDependencies.json $(pwd)/$Vendors/.$Vendors.json
fi

# Cmake process
rm -rf build
mkdir -p build
cmake -S . -B build
cmake --build build
cd build && ctest --verbose --rerun-failed --output-on-failure
cd ..