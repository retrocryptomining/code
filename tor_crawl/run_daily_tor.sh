#!/bin/bash
# Set USER variable to your username
USER=crawl
# Tor_Crawler is clone of https://github.com/alex-miller-0/Tor_Crawler
scriptdir=/home/$USER/Tor_Crawler/src
cd $scriptdir
datestr=`date +%m-%d-%Y`
staticsite=https://SOME/STATIC/URL
sitemd5=$(curl $staticsite | md5sum | awk '{ print $1 }')
echo "Site MD5 is: " $sitemd5

# Note you would need to create the results directory for results, and process them afterwards!
sudo python3 tor_fetch_from_all_current_local_exits.py --url $staticsite --md5 $sitemd5 --outfile results/results_all_listed_tor_exits_$datestr.csv --threads 10

