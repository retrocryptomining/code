import io
import pycurl
import hashlib
import stem.process
import binascii
from stem.util import term
from stem.control import Controller
from stem.descriptor import parse_file
from stem.descriptor.remote import DescriptorDownloader
import argparse
import sys
import requests
import time
import threading
import os

SOCKS_PORT = 7000

# Using STEM to control tor processes is great but...
# you can't use a timeout argument when starting if you are running tor
# from a thread. Therefore we need to subclass threading.Thread and
# provide a shutdown method which we can call.
# The problem is that sometimes tor fails to startup, so we never get a
# handle to the tor process from stem.process.launch_tor_with_config.
# Since we are forcing an exit, sometimes tor fails to create a circuit
# and hangs, sometimes it just fails to initialize and we are left with
# no handle and a process that just sits.
# Adding the PidFile option when starting tor gets us the pid, we then
# need to read that file and kill the pid when the shutdown method is called.
# Then, to ensure we don't have zombies, we also need to wait on that pid.
# This is why we can't have nice things (threads suck). But they're needed
# here so we can have a shared lock on the output file, and there's not a
# better way to parallelize. If we don't parallelize, we have to wait ~90
# seconds whenever one of the tor's fails to initialize and we're f***ed.
class TorCheckThread(threading.Thread):
  def __init__(self, exit_ip, url, outfile, md5, next_socks_port, filelock, results, ip_check_url, static_ip):
    self.exit_ip = exit_ip
    self.url = url
    self.outfile = outfile
    self.md5 = md5
    self.socks_port = next_socks_port
    self.filelock = filelock
    self.results = results
    self.ip_check_url = ip_check_url
    self.static_ip = static_ip
    self.tor_process = None
    self.force_stop = False
    threading.Thread.__init__(self)

  def shutdown(self):
    self.force_stop = True
    if (self.tor_process is not None):
      print("Shutting down (grumpily) tor fetch on socks port %d" % (self.socks_port))
      ## THEORY: attempting to clean up can get us in a weird state where we are waitpid'ing
      ## on the same process id twice, if by some chance between the shutdown call and the
      ## actual cleanup self.tor_process has been populated.
      # Attempt cleanup, but in all likelihood the tor startup has hung and we need to kill
      self.cleanup()
    #else:
    # Get pid and kill it forcefully
    with open(self.pid_path, "r") as pidfile:
      pidline = pidfile.readline()
      pid = int(pidline.strip())
      print("Got pid %d for hung tor process, KILLING" % (pid))
      try:
        os.kill(pid, 9)
      except ProcessLookupError:
        pass
      try:
        #os.wait()
        os.waitpid(pid, 0)
      except ChildProcessError:
        pass
    return

  def cleanup(self):
    if (self.tor_process is not None):
      print("Shutting down cleanly on socks port %d" % (self.socks_port))
      with open(self.pid_path, "r") as pidfile:
        pidline = pidfile.readline()
        pid = int(pidline.strip())
        try:
          self.tor_process.kill()  # stops tor
        except ProcessLookupError:
          pass
        print("Waiting on pid %d for shutting down tor process" % (pid))
        try:
          os.wait3(os.WNOHANG)
          #os.wait()
          #os.waitpid(pid, 0)
        except ChildProcessError:
          pass
    return

  def run(self):
      print(term.format("Starting Tor with socks port %d:\n", term.Attr.BOLD) % (self.socks_port))
      max_fail = 4
      failed = 0
      self.pid_path = '/tmp/tor%d/tor.pid' % (self.socks_port)
      exit_str = None

      # If exit ip is an ipv4 address
      if len(self.exit_ip) <= 16:
        exit_str = "%s/32" % (self.exit_ip)
      else: # Assume exit ip is a digest
        exit_str = self.exit_ip
      while (failed < max_fail) and (self.force_stop == False):
        try:
          self.tor_process = stem.process.launch_tor_with_config(
            config={
              'SocksPort': str(self.socks_port),
              'DataDirectory': '/tmp/tor%d' % (self.socks_port),
              # 'ExitNodes': '{ru}',
              'ExitNodes': exit_str,
              'PidFile' : self.pid_path,
            },
            init_msg_handler=print_bootstrap_lines,
          )
          print("Tor started.")
          # Success!
          break
        except Exception as e:
          failed += 1
          print(e)
          print("Failed to start tor (try %d), retrying?" % (failed))

      if failed == max_fail or self.force_stop == True:
        print("Failing with tor not bootstrapping properly")
        self.results['num_fails'] += 1
        self.cleanup()
        return None

      # print(dir(tor_process))
      max_fail = 2
      failed = 0
      exit_ip = None
      while (exit_ip == None) and (failed < max_fail):
        print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
        exit_ip = query(self.ip_check_url, self.socks_port)
        if exit_ip == None:
          failed += 1
          print("Failed to fetch exit IP from endpoint (try %d), retrying?" % (failed))
        else:
          exit_ip = exit_ip.decode('utf-8')

      if exit_ip == None:
        self.cleanup()
        print("Failing with inability to fetch exit ip")
        self.results['num_fails'] += 1
        return None

      print(term.format(exit_ip, term.Color.BLUE))
      max_fail = 2
      failed = 0
      result = None

      while (result == None) and (failed < max_fail):
        result = query(self.url, self.socks_port)
        if result == None:
          failed += 1
          print("Failed to fetch from endpoint (try %d), retrying?" % (failed))
        m = hashlib.md5()
        m.update(result)

      if result == None:
        print("Failing with inability to fetch target page")
        self.results['num_fails'] += 1
        self.cleanup()
        return None

      try:
        h = binascii.hexlify(m.digest()).decode('utf-8')
        # print(binascii.hexlify(m.digest()).decode('utf-8'))
      except:
        pass
        # print("Failed to print digest")
      sys.stderr.write("%s, %s\n" % (exit_ip, h))
      self.filelock.acquire()
      f = open(self.outfile, "a")
      f.write("%s, %s\n" % (exit_ip, h))
      f.close()
      self.filelock.release()
      if h != self.md5:
        print("Hashes didn't match!")
        self.results['num_hash_mismatch'] += 1
        f = open(h, "w")
        f.write(result.decode('utf-8'))
        f.close()
      else:
        self.results['num_hash_correct'] += 1
      self.cleanup()
      return True

def get_time_seconds():
  return int(time.time())

def get_exit_addresses_remote(exit_ip, exit_port=443):
  downloader = DescriptorDownloader(
    use_mirrors=True,
    timeout=10,
  )
  exit_ips = []
  exit_fingerprints = []
  query = downloader.get_server_descriptors()
  total_exits = 0
  total_allowed_exits = 0
  for desc in query.run():
    try:
      if desc.exit_policy.is_exiting_allowed():
        total_exits += 1
        if desc.exit_policy.can_exit_to(exit_ip, exit_port):
          total_allowed_exits += 1
          exit_ips.append(desc.address)
          exit_fingerprints.append(desc.fingerprint)
      # print(desc.exit_policy)
      # print(dir(desc.exit_policy))
      # print('  %s (%s)' % (desc.nickname, desc.fingerprint))
      #print(desc.address)

      # print('Query took %0.2f seconds' % query.runtime)
    except Exception as exc:
      print('Unable to retrieve the server descriptors: %s' % exc)

  print("Found %d total exits, %d allowing %s on port %d" % (total_exits, total_allowed_exits, exit_ip, exit_port))
  return exit_ips, exit_fingerprints

def get_exit_addresses(exit_ip, exit_port=443):
  exits = []
  total_exits = 0
  total_allowed_exits = 0
  with Controller.from_port(port=9051) as controller:
    controller.authenticate()

    exit_digests = set()
    data_dir = controller.get_conf('DataDirectory')

    for desc in controller.get_microdescriptors():
      if desc.exit_policy.is_exiting_allowed():
        total_exits += 1
        if desc.exit_policy.can_exit_to(exit_ip, exit_port):
          #print(vars(desc))
          #print(dir(desc))
          total_allowed_exits += 1
          #print(desc.digest)
          #print(desc.fingerprint)
          exit_digests.add(desc.digest)
          # print(desc)
          #print(desc.or_addresses)
          # print(dir(desc))
    total_digests_found = 0
    for desc in parse_file(os.path.join(data_dir, 'cached-microdesc-consensus')):
    #for desc in parse_file(os.path.join(data_dir, 'cached-microdescs')):
      if desc.digest in exit_digests:
        total_digests_found += 1
        exits.append(desc.address)
        print(desc.flags)
        print(dir(desc))
        print(vars(desc))
  print("Getting exits found %d total exits, %d allowing exit to %s:%d, %d digests found in consensus" % (total_exits, total_allowed_exits, exit_ip, exit_port, total_digests_found))
  return exits, exit_digests


def get_exit_addresses_full_descriptors(exit_ip, exit_port=443):
  exits = set()
  all_exits = set()
  total_exits = 0
  total_allowed_exits = 0
  with Controller.from_port(port=9051) as controller:
    controller.authenticate()

    exit_digests = set()
    data_dir = controller.get_conf('DataDirectory')

    for desc in controller.get_server_descriptors():
      if desc.exit_policy.is_exiting_allowed():
        all_exits.add(desc.fingerprint)
        if desc.exit_policy.can_exit_to(exit_ip, exit_port):
          #print(vars(desc))
          #print(dir(desc))
          total_allowed_exits += 1
          exit_digests.add(desc.fingerprint)
          exits.add(desc.address)
          #print(desc.digest)
          #print(desc.fingerprint)
          #exit_digests.add(desc.digest)
          # print(desc)
          #print(desc.or_addresses)
          # print(dir(desc))

  print("Getting exits found %d total exits, %d allowing exit to %s:%d" % (len(all_exits), len(exits), exit_ip, exit_port))
  return exits, exit_digests

def query(url, socks_port):
  """
  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
  """

  output = io.BytesIO()

  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, socks_port)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.WRITEFUNCTION, output.write)
  query.setopt(pycurl.TIMEOUT, 30)

  try:
    query.perform()
    return output.getvalue()
  except pycurl.error as exc:
    print("Unable to reach %s (%s)" % (url, exc))
    return None

# Start an instance of Tor configured to only exit through a specific IP. This prints
# Tor's bootstrap information as it starts. Note that this likely will not
# work if you have another Tor instance running.

def print_bootstrap_lines(line):
  if "Bootstrapped " in line:
    print(term.format(line, term.Color.BLUE))


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--url', dest='url', default=None,
                      help='URL to fetch')
  parser.add_argument('--md5', dest='md5', default=None,
                      help='Expected md5 sum of downloaded file')
  parser.add_argument('--outfile', dest='outfile', default=None,
                      help='Output file to write results to')
  parser.add_argument('--threads', dest='threads', default=2,
                      help='Number of concurrent tor processes/exits to test')
  parser.add_argument('--ip-check-url', dest='ip_check_url', default='https://ipinfo.io',
                      help='URL that returns a single string as the IP address server saw connecting')
  parser.add_argument('--static-host-ip', dest='static_host_ip', default='1.2.3.4',
                      help='IP address for webserver host, to check if exit is allowed')

  args = parser.parse_args()
  if args.url is None or args.md5 is None or args.outfile is None:
    sys.stdout.write("Must provide all arguments\n")
    sys.exit(1)
  args.threads = int(args.threads)
  #exits, digests = get_exit_addresses()
  #exits, digests = get_exit_addresses_remote()
  exits, digests = get_exit_addresses_full_descriptors(args.static_host_ip)
  #sys.exit()
  results = {'num_success': 0, 'num_fails': 0, 'num_hard_fails': 0, 'num_hash_correct': 0, 'num_hash_mismatch': 0}
  count_running = 0
  thread_list = []
  thread_times = {}
  filelock = threading.Lock()
  print("Starting tor exit test on %d exits with %d threads" % (len(exits), args.threads))
  next_socks_port = SOCKS_PORT
  #for exit_ip in exits: # Normal method, use exits found in consensus
  for exit_ip in digests:  # Normal method, use exits found in microdescs
    while (len(thread_list) >= args.threads):
      print("Main thread loop")
      time.sleep(1)
      to_remove = []
      for t in thread_list:
        if not t.isAlive():
          to_remove.append(t)
        elif thread_times[t] + 60 < get_time_seconds():
          print("Tor fetcher took longer than 60 seconds, killing?")
          t.shutdown()
          to_remove.append(t)
          pass
          # time out a thread if it runs for three minutes
          #to_remove.append(t)
          #t.join(1)
      for t in to_remove:
        # Join not needed due to our use of waitpid in the main thread
        # (but shouldn't *hurt*).
        # However when waitpid hangs (due to unknown pid?) join then
        # hangs, causing us to get stuck. Ugh.
        ## Made change in how shutdown works, so trying with join again. dubble ugh.
        print("Joining thread for socks port %d" % (t.socks_port))
        try:
          t.join(1.0)
        except:
          print("Join failed? Continuing?")
          pass
      thread_list = [t for t in thread_list if not t in to_remove]
    print("attempting to fetch from %s" % (exit_ip))
    try:
      #tor_fetch_from_ip(exit_ip, args.url, args.outfile, args.md5, next_socks_port, filelock)
      #new_thread = threading.Thread(target=tor_fetch_from_ip, args=(exit_ip, args.url, args.outfile, args.md5, next_socks_port, filelock, results))
      new_thread = TorCheckThread(exit_ip, args.url, args.outfile, args.md5, next_socks_port, filelock, results, args.ip_check_url, args.static_host_ip)
      thread_list.append(new_thread)
      thread_times[new_thread] = get_time_seconds()
      new_thread.start()
      next_socks_port += 1
      #if result is not True:
      #  num_fails += 1
      #else:
      #  num_success += 1
    except:
      print("Failed to fetch using exit. Will continue nonetheless!")
      num_hard_fails += 1
  print("%d successful, %d fails, %d HARD fails, %d hash match, %d hash mismatch\n" % (results['num_success'], results['num_fails'], results['num_hard_fails'], results['num_hash_correct'], results['num_hash_mismatch']))


if __name__ == "__main__":
  main()
