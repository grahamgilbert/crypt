#!/bin/bash

pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd`


# based on http://tgoode.com/2014/06/05/sensible-way-increment-bundle-version-cfbundleversion-xcode
if git rev-parse --is-inside-work-tree 2> /dev/null > /dev/null; then
    build_number=$(git rev-list HEAD --count)
    echo $build_number
fi
popd > /dev/null
