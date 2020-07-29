# Contents

This directory contains code for scanning Tor exit nodes for injection. Author: Nathan S. Evans <nathan.s.evans at du.edu>.
 
The methodology for this scan is incredibly simple (naive?).

 Step 1: Grab a static web page from somewhere on the Internet. Calculate the MD5 hash of the content.
 Step 2: Using STEM, grab all valid exit nodes from Tor, and fetch the same static page via each exit.
 Step 3: If the hash of the page fetched via Tor is different than the original, save the content.
 Step 4: Check the different hashes to see if they include cryptojacking software. 
         NOTE on step 4: Originally the goal was to have this step be automated, but since the 
                         vast majority of exits don't tamper with content (at least in our testing)
                         we did this checking manually. However, there is a script that does it as 
                         well.


Files/directories:

run_daily_tor.sh:
  shell script to run 'tor_fetch_from_all_current_local_exits.py'. Intended to be 
  run as a cron job, or manually. Sets up variables for same.

tor_fetch_from_all_current_local_exits.py: 
  python program that leverages STEM to fetch exits from a running Tor instance, 
  then iterates over each of these exits to grab the static web page. Compares the
  MD5 hash of the response with the original (provided on the command line) and writes
  out the results if the hash doesn't match.
  Command line example: python3 tor_fetch_from_all_current_local_exits.py --url $staticsite --md5 $sitemd5 --outfile results/results_all_listed_tor_exits_$datestr.csv --threads 10 
  See run_daily_tor.sh for information on what the variables might be.

process_result_file.py:
  python script to process the results files. Finds non-matching hashes and checks their content
  for various cryptomining strings. Not reliable: paper results were checked manually due to the
  small number of true positives ever found.
  Command line example: for i in `ls -tr results/results_all_listed_tor*.csv`;do python process_result_file.py --md5=02b4561b78fa16e5650a45410022c606 --infile=$i --outfile summary --hashdir ./results/hashes/;done

process_results_cmd.sh:
  Shell script to check result files to see if content includes cryptomining software.
