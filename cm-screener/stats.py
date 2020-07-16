import sys
import re


if len(sys.argv) != 2:
    print("Usage: " + sys.argv[0] + " INPUTDIR")
    exit(-1)

infh = None

try:
    infh = open(sys.argv[1] + "/cryptominer-scanner.log")
except Exception, e:
    print("Could not open input file: %s", sys.argv[1] + "/cryptominer-scanner.log")

error_count = 0
timeout_count = 0
reset_count = 0
missed_redirect_count = 0
read_loop_peek_count = 0
conn_refused_count = 0

start_time = 0
end_time = 0

time_re = re.compile('TIME: (.*)"')

for line in infh:
    if "STARTTIME" in line:
        start_time = int(time_re.search(line).group(1))
    if "ENDTIME" in line:
        end_time = int(time_re.search(line).group(1))
    if "level=error" in line:
        error_count += 1
    if "Client.Timeout" in line:
        timeout_count +=1 
    if "connection reset" in line:
        reset_count += 1
    if "TOO_MANY" in line:
        missed_redirect_count += 1
    if "readLoopPeek" in line:
        read_loop_peek_count += 1
    if "connection refused" in line:
        conn_refused_count += 1

infh.close()
scan_time = round( (end_time - start_time) / 60.0, 2)


try:
    infh = open(sys.argv[1] + "/output.csv")
except Exception, e:
    print("Could not open input file: %s", sys.argv[1] + "/output.csv")

line_count = 0
for line in infh:
    line_count += 1
infh.close()


print(scan_time)
print("Output: " + str(line_count))
print("Errors: " + str(error_count))
print("Missed redirects: " + str(missed_redirect_count))
print("Timeouts: " + str(timeout_count))
print("Resets: " + str(reset_count))
print("readLoopPeek: " + str(read_loop_peek_count))
print("Connection refused: " + str(conn_refused_count))
