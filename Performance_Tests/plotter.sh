#!/bin/sh
#
# Luke Hall B425724 - Part C Project 
# Shell script to take an iperf results file and create gnuplot showing resultant data
#

# Arguments & Variables
INPUT_FILE=$1
OUTPUT_FILE=$2
TEMP_FILE="temp_result.txt"
TCP_TITLE="TCP Flow"
UDP_TITLE="UDP Flow"

echo "Attempting to read $INPUT_FILE"

if [ -f "$INPUT_FILE" ]; then
    # File found
    echo "File found... reading"
    # Format file to gnuplot data
    cat $INPUT_FILE | grep sec | head -15 | tr - " " | awk '{print $4, $8}' > ./$TEMP_FILE
else
    # File not found
    echo "ERROR :: No file found"
fi
echo "File read & data filtered"

# Create gnuplot of filtered data
if (grep -q TCP "$INPUT_FILE") || (grep -q tcp "$INPUT_FILE"); then
    gnuplot -persist <<-EOFMARKER
        set title "TCP Test"
	set xrange [1:15]
	set xtics 1,1,15
	set yrange [12:16]
	set ytics 12,0.5,16
	set xlabel "Time (sec)"
	set ylabel "Throughput (Gbps)
	set terminal png
	set output "$OUTPUT_FILE.png"
	plot "$TEMP_FILE" title "TCP flow" with linespoints
EOFMARKER
else
    gnuplot -persist <<-EOFMARKER
        set title "UDP Test"
	set xrange [1:15]
	set xtics 1,1,15
	set yrange [12:16]
	set ytics 12,0.5,16
	set xlabel "Time (sec)"
	set ylabel "Throughput (Gbps)
	set terminal png
	set output "$OUTPUT_FILE.png"
	plot "$TEMP_FILE" title "UDP flow" with linespoints
EOFMARKER
fi
echo "Graph created :: $OUTPUT_FILE.png"
# Sort output .png to folders & clean up temp files
rm ./$TEMP_FILE

if grep -q dumb "$OUTPUT_FILE.png";then
    mv $OUTPUT_FILE.png LearningL2/$OUTPUT_FILE.png
else
    mv $OUTPUT_FILE.png DumbL2/$OUTPUT_FILE.png
fi


