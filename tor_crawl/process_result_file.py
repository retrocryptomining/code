import argparse

known_coin_strings = ["proxy.tntcode.com", "CryptoNoter", "coinhive", "jsecoin", "cryptominerrock", "inwemo.min.js", "miner.js", "socketminer.com", "miner.min.js", "inwemo.min.js", "projectpoi.min.js"]
known_error_strings = ["zscaler", "fba_login", "ERR_ACCESS_DENIED", "Unauthorized", "js.union-wifi", "Access Denied", "Gateway Timeout", "Not Found"]
known_injection_strings = ["netbro_cache_analytics"]

def count_file_occurences(filename, test_string):
    count_found = 0
    with open(filename, "r") as infile:
        for line in infile:
            if test_string.lower() in line.lower():
                count_found += 1
    return count_found

def check_known_miner(filename):
    result = False
    for test_string in known_coin_strings:
        if count_file_occurences(filename, test_string) > 0:
            result = True
    return result

def check_known_error(filename):
    result = False
    for test_string in known_error_strings:
        if count_file_occurences(filename, test_string) > 0:
            result = True
    return result

def check_known_injection(filename):
    result = False
    for test_string in known_injection_strings:
        if count_file_occurences(filename, test_string) > 0:
            result = True
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--infile', dest='infile', default=None, required=True,
                      help='Input file to process')
    parser.add_argument('--outfile', dest='outfile', default=None, required=True,
                      help='Output file to write results to (append)')
    parser.add_argument('--md5', dest='md5', default=None, required=True,
                      help='Expected md5 hash of web page')
    parser.add_argument('--hashdir', dest='hashdir', default=None, required=True,
                      help='Location of result files (hash is name of file)')

    args = parser.parse_args()

    total_count = 0
    correct_count = 0
    miner_count = 0
    error_count = 0
    other_injection_count = 0
    other_md5_count = 0
    with open(args.infile, "r") as infile:
        for line in infile:
            line = line.strip()
            data = line.split(",")
            if (len(data) >= 2):
                total_count += 1
                # Hash is always last element
                md5 = data[len(data) - 1].lstrip()
                ip = data[len(data) - 2]
                #print("Comparing `%s' to `%s'" % (md5, args.md5))
                if md5 == args.md5:
                    correct_count += 1
                else:
                    if check_known_miner("%s/%s" % (args.hashdir, md5)) == True:
                        print("Found miner! ip: %s, hash %s" % (ip, md5))
                        miner_count += 1
                    elif check_known_error("%s/%s" % (args.hashdir, md5)) == True:
                        error_count += 1
                    elif check_known_injection("%s/%s" % (args.hashdir, md5)) == True:
                        other_injection_count += 1
                    else:
                        other_md5_count += 1
    #print("%d total results, %d correct, %d miners, %d known errors, %d other known injections" % (total_count, correct_count, miner_count, error_count, other_injection_count))
    # date is part of file name. bad thinking on my part, per usual.
    parts = args.infile.split("_")
    #print("Date is %s" % parts[-1].split('.')[0])
    temp_date = parts[-1].split('.')[0]
    # csv data will have:
    # DATE,total_exits_scanned,total_exits_correct,total_miners_found,known_error_count,known_injection_count,other_md5
    with open(args.outfile, "a") as outfh:
        outfh.write("%s,%d,%d,%d,%d,%d,%d\n" % (temp_date, total_count, correct_count, miner_count, error_count, other_injection_count, other_md5_count))




if __name__ == "__main__":
    main()
