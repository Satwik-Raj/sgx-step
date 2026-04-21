#!/bin/bash

# Number of runs
RUNS=200
length=128
sum=0
count=0

# Build step
make clean &> /dev/null
make &> /dev/null

for ((i=1; i<=RUNS; i++)); do
    echo "Run $i"

    sleep 2

    # Run the program
    sudo ./app &> /dev/null

    # Read results.txt
    if [[ -f results.txt ]]; then
        rec_idx=$(sed -n '1p' results.txt)
        value=$(sed -n '2p' results.txt)
        echo "  rec_idx: $rec_idx | acc: $value%"
        # Only consider rec_idx == length
        if [[ "$rec_idx" -eq $length ]]; then
            sum=$(echo "$sum + $value" | bc)
            count=$((count + 1))
        fi
    else
        echo "results.txt not found!"
    fi
done
echo
echo "rec_idx == $length occurred $count times out of $RUNS runs"
echo
# Compute average
if [[ $count -gt 0 ]]; then
    avg=$(echo "scale=4; $sum / $count" | bc)
    echo "Average (rec_idx == $length): $avg"
else
    echo "No valid runs with rec_idx == $length"
fi
