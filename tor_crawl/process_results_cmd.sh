for i in `ls -tr results/results_all_listed_tor*.csv`;do python process_result_file.py --md5=02b4561b78fa16e5650a45410022c606 --infile=$i --outfile summary --hashdir ./results/hashes/;done
