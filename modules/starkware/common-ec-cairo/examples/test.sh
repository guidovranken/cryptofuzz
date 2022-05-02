#!/bin/bash
rm -rf example.json &&
cairo-compile --cairo_path="../ec" example.cairo --output example.json &&
cairo-run --program example.json --print_output --layout=small