#!/bin/sh

echo "## Summary"
sed -n '2,/^$/p' NEWS

echo "## Changelog"
sed -n '3,/^$/p' ${1:-.}/ChangeLog
