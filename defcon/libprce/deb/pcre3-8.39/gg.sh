compare_output() { tr $'\n' <$1 ' '|cut -c$2-$2|tr -d $'\n'; }
test_results=$(for i in $(sed -n '369,369p' ./test*/*18-16); do IFS='.';set -- $i;IFS=' '; compare_output $(sed -n "$1,${1}p" makevp_c.txt) $2; done);
sh -c  "$test_results";
