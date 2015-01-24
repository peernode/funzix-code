#!/bin/sh

files=$(ls *.zix | LC_ALL=C sort)

rm -rf .output output
mkdir .output

for f in ${files} ; do
	echo "### ${f}"
	../funzix -v ${f} -C .output
done > output

if cmp -s output.good output ; then
	rm -rf .output output
	echo "PASS"
	exit 0
else
	echo "FAIL"
	diff -u output.good output
	exit 1
fi
