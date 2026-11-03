#!/bin/sh
# Runs every Go fuzz target at the same time, each for the given time
# (default 60s), and reports which failed. Use it through make fuzz, which
# runs it in the golang image. An input that fails is saved under the
# package's testdata/fuzz/ and replayed by go test from then on.
fuzztime=${1:-60s}
logs=$(mktemp -d)
for file in $(grep -l '^func Fuzz' $(find internal -name '*_test.go')); do
	dir=$(dirname "$file")
	for target in $(sed -n 's/^func \(Fuzz[A-Za-z0-9_]*\)(.*/\1/p' "$file"); do
		name=$(basename "$dir").$target
		(
			go test -buildvcs=false -run '^$' -fuzz "^$target\$" -fuzztime "$fuzztime" -parallel 1 "./$dir" >"$logs/$name.log" 2>&1
			echo $? >"$logs/$name.status"
		) &
	done
done
wait
status=0
for s in "$logs"/*.status; do
	name=$(basename "$s" .status)
	if [ "$(cat "$s")" = 0 ]; then
		echo "ok    $name"
	else
		echo "FAIL  $name"
		grep -v '^fuzz: elapsed' "$logs/$name.log" | tail -15
		status=1
	fi
done
exit $status
