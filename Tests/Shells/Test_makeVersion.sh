#!/bin/bash
# All tests are executed from the project root (i.e., the current working directory is the project root)
# Including the libraries
source $(pwd)/Shells/makeVersion.sh

versionLocation="$(pwd)/Settings/.version"
verString="apps.version=0.0.0"

makeVersion "$versionLocation" "$verString" "#"
# makeVersion "$versionLocation" "$verString"
# makeVersion "$versionLocation" "$verString" "##"
# makeVersion "$versionLocation" "$verString" "###"
# makeVersion "$versionLocation" "$verString" "####"