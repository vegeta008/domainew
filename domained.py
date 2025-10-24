#!/usr/bin/env python3

# #Domain name enumeration tool that leverages awesome tools:
#     - Sublist3r by Ahmed Aboul-Ela (https://github.com/aboul3la/Sublist3r)
#     - enumall by Jason Haddix (https://github.com/jhaddix/domain)
#     - Knock by Gianni Amato (https://github.com/guelfoweb/knock)
#     - Subbrute by TheRook (https://github.com/TheRook/subbrute)
#     - massdns by B. Blechschmidt (https://github.com/blechschmidt/massdns)
#     - Amass by Jeff by Foley (https://github.com/OWASP/Amass)
#     - SubFinder by Ice3man543 (https://github.com/subfinder/subfinder)
#     - Recon-ng by Tim Tomes (LaNMaSteR53) (https://bitbucket.org/LaNMaSteR53/recon-ng)
#     - EyeWitness by ChrisTruncer (https://github.com/FortyNorthSecurity/EyeWitness)
#     - SecList (DNS Recon List) by Daniel Miessler (https://github.com/danielmiessler/SecLists)
#     - LevelUp All.txt Subdomain List by Jason Haddix

# # Github - https://github.com/cakinney (Caleb Kinney)

import argparse
import configparser
import colorama
import datetime
import glob
import itertools
import os
import sys
import re
import requests
import smtplib
import time
import subprocess
import threading
import shlex
from signal import signal, alarm, SIGALRM
from installer import upgradeFiles
from color import error, info, debug, warning, colored
from shutil import which

colorama.init()
today = datetime.date.today()

api_settings = None
shodan_enabled = False
shodan_api_key = None
securitytrails_enabled = False
securitytrails_api_key = None
aggregated_hosts = set()
scope_file_path = None
output_dir = None


def get_args():
    parser = argparse.ArgumentParser(description="domained")
    parser.add_argument(
        "-d", "--domain", type=str, help="Domain", required=False, default=False
    )
    parser.add_argument(
        "-s",
        "--secure",
        help="Secure",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-b", "--bruteforce", help="Bruceforce", action="store_true", default=False
    )
    parser.add_argument("--upgrade", help="Upgrade", action="store_true", default=False)
    parser.add_argument("--install", help="Install", action="store_true", default=False)
    parser.add_argument("--vpn", help="VPN Check", action="store_true", default=False)
    parser.add_argument(
        "-p", "--ports", help="Ports", action="store_true", default=False
    )
    parser.add_argument(
        "-q", "--quick", help="Quick", action="store_true", default=False
    )
    parser.add_argument(
        "--bruteall", help="Bruteforce JHaddix All", action="store_true", default=False
    )
    parser.add_argument(
        "--fresh", help="Remove output Folder", action="store_true", default=False
    )
    parser.add_argument(
        "--notify",
        help="Notify when script completed",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--active", help="EyeWitness Active Scan", action="store_true", default=False
    )
    parser.add_argument(
        "--noeyewitness", help="No EyeWitness", action="store_true", default=False
    )
    parser.add_argument(
        "--knock-timeout",
        type=float,
        help="Timeout (seconds) for Knockpy network requests",
        default=None,
    )

    return parser.parse_args()


newpath = r"output"
if not os.path.exists(newpath):
    os.makedirs(newpath)


def ensure_python_module(module_name, install_hint=None):
    try:
        __import__(module_name)
    except ImportError:
        hint = f" ({install_hint})" if install_hint else ""
        warning(f"\nMissing required module '{module_name}'{hint}. Skipping.\n")
        return False
    return True


class ProgressIndicator:
    def __init__(self, label, stream=None):
        self.label = label
        self.stream = stream or sys.stdout
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._frames = itertools.cycle("|/-\\")
        self._thread = None

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def _animate(self):
        padding = len(self.label) + 6
        while not self._stop_event.is_set():
            frame = next(self._frames)
            with self._lock:
                self.stream.write(f"\r{self.label} [{frame}]")
                self.stream.flush()
            time.sleep(0.1)
        with self._lock:
            self.stream.write("\r" + " " * padding + "\r")
            self.stream.flush()

    def write(self, message):
        if message is None:
            return
        cleaned = message.rstrip("\n")
        padding = len(self.label) + 6
        with self._lock:
            self.stream.write("\r" + " " * padding + "\r")
            if cleaned:
                self.stream.write(f"{cleaned}\n")
            self.stream.flush()

    def stop(self):
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join()
        self._thread = None


def run_command_with_progress(command, label, cwd=None):
    spinner = ProgressIndicator(label)
    spinner.start()
    try:
        use_shell = isinstance(command, str)
        try:
            proc = subprocess.Popen(
                command,
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=cwd,
            )
        except FileNotFoundError as exc:
            spinner.write(f"{label} error: {exc}")
            return 127

        for line in proc.stdout or []:
            spinner.write(line)
        return proc.wait()
    finally:
        spinner.stop()


def execute_tool(command, tool_name, cwd=None):
    info(f"\n\nRunning {tool_name} \n")
    returncode = run_command_with_progress(command, f"{tool_name} en progreso", cwd=cwd)
    if returncode == 0:
        info(f"\n{tool_name} Complete")
    else:
        warning(f"\n{tool_name} exited with status code {returncode}")
    time.sleep(1)
    return returncode


def run_httpx_validation(scope_file, output_file, validated_file, cwd=None):
    if not which("httpx-toolkit"):
        warning("\nhttpx-toolkit not found in PATH. Skipping validation step.\n")
        return False

    httpx_cmd = "httpx-toolkit -l {} -v -silent -probe -server -sc -o {}".format(
        shlex.quote(scope_file), shlex.quote(output_file)
    )
    debug("\nRunning Command: {}".format(httpx_cmd))
    result = execute_tool(httpx_cmd, "httpx-toolkit", cwd=cwd)
    if result != 0:
        warning("\nhttpx-toolkit reported an error. Validation output may be incomplete.\n")
        return False

    info(f"\nhttpx-toolkit output saved to {output_file}")
    try:
        with open(output_file, "r") as src, open(validated_file, "w") as dst:
            for line in src:
                cleaned = line.strip()
                if not cleaned:
                    continue
                url = cleaned.split()[0]
                dst.write(f"{url}\n")
    except OSError as exc:
        error(f"\nUnable to process httpx output: {exc}\n")
        return False

    info(f"\nValidated hosts saved to {validated_file}")
    return True


def run_httpx_for_aggregated_hosts():
    global scope_file_path, aggregated_hosts
    if not aggregated_hosts:
        warning("\nNo targets collected for httpx-toolkit.\n")
        return

    combined_scope = sorted(aggregated_hosts)
    scope_file = scope_file_path or os.path.join(script_path, "scope.txt")
    try:
        with open(scope_file, "w") as scope_handle:
            for host in combined_scope:
                scope_handle.write(f"{host}\n")
        scope_file_path = scope_file
        info(f"\nCombined scope list saved to {scope_file}")
    except OSError as exc:
        error(f"\nUnable to write combined scope file: {exc}\n")
        return

    info(f"\nTotal targets for httpx-toolkit: {len(combined_scope)}")
    httpx_output = os.path.join(script_path, "archivofprobe.txt")
    validated_output = os.path.join(script_path, "finalvalidado.txt")
    run_httpx_validation(scope_file, httpx_output, validated_output, cwd=script_path)


def banner():
    warning(
        "\n         ___/ /__  __ _  ___ _(_)__  ___ ___/ /\n"
        "        / _  / _ \\  ' \\ / _ `/ / _ \\ -_) _  /\n"
        "        \\_,_/\\___/_/_/_/\\_,_/_/_//_/\\__/\\_,_/\n"
        "    {}\t\t\tgithub.com/cakinney{}".format(
            colorama.Fore.BLUE, colorama.Style.RESET_ALL
        )
    )
    globpath = "*.csv"
    globpath2 = "*.lst"
    if (next(glob.iglob(globpath), None)) or (next(glob.iglob(globpath2), None)):
        info("\nThe following files may be left over from failed domained attempts:")
        for file in glob.glob(globpath):
            info("  - {}".format(file))
        for file in glob.glob(globpath2):
            info("  - {}".format(file))
        signal(SIGALRM, lambda x: 1 / 0)
        try:
            alarm(5)
            RemoveQ = input("\nWould you like to remove the files? [y/n]: ")
            if RemoveQ.lower() == "y":
                os.system("rm *.csv")
                os.system("rm *.lst")
                info("\nFiles removed\nStarting domained...")
                time.sleep(5)
            else:
                info("\nThank you.\nPlease wait...")
                time.sleep(1)
        except:
            info("\n\nStarting domained...")


def sublist3r(brute=False):
    if not ensure_python_module("dns", "pip install dnspython"):
        return
    sublist3rFileName = "{}_sublist3r.txt".format(output_base)
    sublist3r_script = os.path.join(script_path, "bin/Sublist3r/sublist3r.py")
    sublist3r_cmd = [
        "python3",
        sublist3r_script,
        "-v",
        "-t",
        "15",
    ]
    if brute:
        sublist3r_cmd.append("-b")
    sublist3r_cmd.extend(["-d", domain, "--output", sublist3rFileName])
    Subcmd = " ".join(sublist3r_cmd)
    debug("\nRunning Command: {}".format(Subcmd))
    execute_tool(Subcmd, "Sublist3r")
   

def fprobe ():
    info("\n\nRunning fprobe \n")
    fprobeCMD = "fprobe -i {} -t 100 -p xlarge > {} {}".format(
       # os.path.join(script_path, ""), domain
    )
    debug("\nRunning Command: {}".format(fprobeCMD))
    os.system(fprobeCMD)
    info("\fprobe Complete")
    time.sleep(1)

def enumall():
    python2 = which("python2") or which("python2.7")
    if not python2:
        warning("\nPython2 interpreter not found. Skipping enumall.\n")
        return
    enumall_script = os.path.join(script_path, "bin/domain/enumall.py")
    if not os.path.exists(enumall_script):
        warning("\nEnumall script not found. Skipping.\n")
        return
    enumallCMD = "{} {} {}".format(python2, enumall_script, domain)
    debug("\nRunning Command: {}".format(enumallCMD))
    execute_tool(enumallCMD, "Enumall")


def massdns():
    word_file = os.path.join(
        script_path, "bin/sublst/all.txt" if bruteall else "bin/sublst/sl-domains.txt"
    )
    massdnsCMD = "python {} {} {} | {} -r resolvers.txt -t A -o S -w {}-massdns.txt".format(
        os.path.join(script_path, "bin/subbrute/subbrute.py"),
        word_file,
        domain,
        os.path.join(script_path, "bin/massdns/bin/massdns"),
        output_base,
    )
    debug("\nRunning Command: {}".format(massdnsCMD))
    execute_tool(massdnsCMD, "MassDNS")


def knockpy(timeout=None):
    required_modules = [
        ("bs4", "pip install beautifulsoup4"),
        ("dns", "pip install dnspython"),
        ("OpenSSL", "pip install pyopenssl"),
        ("tqdm", "pip install tqdm"),
    ]
    for module_name, hint in required_modules:
        if not ensure_python_module(module_name, hint):
            return

    knockpy_root = os.path.join(script_path, "bin/knockpy")
    added_path = False
    if knockpy_root not in sys.path:
        sys.path.insert(0, knockpy_root)
        added_path = True

    try:
        from knock.knockpy import KNOCKPY
    except Exception as exc:
        error(f"\nUnable to import knockpy: {exc}\n")
        if added_path:
            sys.path.remove(knockpy_root)
        return

    try:
        knock_kwargs = {"recon": True, "silent": True}
        if timeout is not None:
            knock_kwargs["timeout"] = timeout
            debug(f"\nKnockpy timeout set to {timeout} seconds\n")
        info("\n\nRunning Knock \n")
        spinner = ProgressIndicator("Knockpy en progreso")
        spinner.start()
        try:
            results = KNOCKPY(domain, **knock_kwargs)
        finally:
            spinner.stop()
    except Exception as exc:
        error(f"\nKnockpy execution failed: {exc}\n")
        if added_path:
            sys.path.remove(knockpy_root)
        return
    finally:
        if added_path and knockpy_root in sys.path:
            sys.path.remove(knockpy_root)

    if not results:
        warning("\nKnockpy returned no results.\n")
        return

    knock_subdomains = []
    for item in results if isinstance(results, list) else [results]:
        host = item.get("domain") if isinstance(item, dict) else None
        if host and host.endswith(domain):
            knock_subdomains.append(host)

    knock_subdomains = sorted(set(knock_subdomains))
    if not knock_subdomains:
        warning("\nKnockpy produced no subdomains matching the target domain.\n")
        return

    knockpyFilename = "{}_knock.txt".format(output_base)
    try:
        with open(knockpyFilename, "w") as f:
            for sub in knock_subdomains:
                f.write(f"{sub}\n")
    except OSError as exc:
        error(f"\nUnable to write Knockpy results: {exc}\n")
        return

    info("\nKnockpy Complete")
    time.sleep(1)


def shodan_subdomains():
    if not shodan_enabled or not shodan_api_key:
        debug("\nShodan integration disabled or missing API key. Skipping.\n")
        return

    info("\n\nRunning Shodan \n")
    shodan_filename = "{}_shodan.txt".format(output_base)
    subdomains = set()
    domain_results = set()
    search_results = set()

    # Attempt to pull results from the Shodan DNS database.
    dns_response = None
    try:
        dns_response = requests.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": shodan_api_key},
            timeout=30,
        )
        dns_response.raise_for_status()
    except requests.HTTPError as exc:
        body = ""
        if dns_response is not None:
            body = f" ({dns_response.status_code}: {dns_response.text})"
        warning(f"\nShodan DNS lookup failed: {exc}{body}\n")
    except requests.RequestException as exc:
        warning(f"\nShodan DNS request error: {exc}\n")
    else:
        try:
            payload = dns_response.json()
        except ValueError as exc:
            warning(f"\nShodan DNS returned invalid JSON: {exc}\n")
        else:
            raw_subdomains = payload.get("subdomains") or []
            if isinstance(raw_subdomains, list):
                domain_results.update(
                    f"{sub}.{domain}"
                    for sub in raw_subdomains
                    if isinstance(sub, str) and sub
                )
            else:
                warning("\nUnexpected Shodan DNS response format for 'subdomains'.\n")
            # The DNS endpoint can also leak additional subdomain names via the data array.
            records = payload.get("data")
            if isinstance(records, list):
                for record in records:
                    sub_name = record.get("subdomain") if isinstance(record, dict) else None
                    if isinstance(sub_name, str) and sub_name:
                        domain_results.add(f"{sub_name}.{domain}")

    subdomains.update(domain_results)

    # Query the standard Shodan search API for hostnames matching the domain.
    search_response = None
    try:
        search_response = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key": shodan_api_key,
                "query": f"hostname:{domain}",
                "minify": "true",
            },
            timeout=30,
        )
        search_response.raise_for_status()
    except requests.HTTPError as exc:
        body = ""
        if search_response is not None:
            body = f" ({search_response.status_code}: {search_response.text})"
        warning(f"\nShodan search failed: {exc}{body}\n")
    except requests.RequestException as exc:
        warning(f"\nShodan search request error: {exc}\n")
    else:
        try:
            payload = search_response.json()
        except ValueError as exc:
            warning(f"\nShodan search returned invalid JSON: {exc}\n")
        else:
            matches = payload.get("matches") or []
            if isinstance(matches, list):
                for match in matches:
                    hostnames = match.get("hostnames") if isinstance(match, dict) else None
                    if isinstance(hostnames, list):
                        for host in hostnames:
                            if isinstance(host, str) and host.endswith(domain):
                                search_results.add(host)
            else:
                warning("\nUnexpected Shodan search response format for 'matches'.\n")

    subdomains.update(search_results)

    try:
        with open(shodan_filename, "w") as handle:
            for host in sorted(subdomains):
                handle.write(f"{host}\n")
    except OSError as exc:
        error(f"\nUnable to write Shodan results: {exc}\n")
        return

    total_found = len(subdomains)
    if total_found:
        info("\nShodan Complete")
        info(f"\n{total_found} Subdomains discovered by Shodan")
        if domain_results:
            info(f"\n  - {len(domain_results)} from Shodan DNS database")
        if search_results:
            info(f"\n  - {len(search_results)} from Shodan search API")
    else:
        warning("\nShodan returned no subdomains.\n")
    time.sleep(1)


def securitytrails_subdomains():
    if not securitytrails_enabled or not securitytrails_api_key:
        debug("\nSecurityTrails integration disabled or missing API key. Skipping.\n")
        return

    info("\n\nRunning SecurityTrails \n")
    response = None
    headers = {
        "Accept": "application/json",
        "APIKEY": securitytrails_api_key,
    }
    try:
        response = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers=headers,
            params={"include_inactive": "true"},
            timeout=30,
        )
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = ""
        if response is not None:
            body = f" ({response.status_code}: {response.text})"
        error(f"\nSecurityTrails query failed: {exc}{body}\n")
        return
    except requests.RequestException as exc:
        error(f"\nSecurityTrails request error: {exc}\n")
        return

    try:
        payload = response.json()
    except ValueError as exc:
        error(f"\nSecurityTrails returned an invalid JSON response: {exc}\n")
        return

    raw_subdomains = payload.get("subdomains") or []
    if not isinstance(raw_subdomains, list):
        warning("\nUnexpected SecurityTrails response format. Skipping.\n")
        raw_subdomains = []

    subdomains = sorted(
        {f"{sub}.{domain}" for sub in raw_subdomains if isinstance(sub, str) and sub}
    )
    securitytrails_filename = "{}_securitytrails.txt".format(output_base)
    try:
        with open(securitytrails_filename, "w") as handle:
            for host in subdomains:
                handle.write(f"{host}\n")
    except OSError as exc:
        error(f"\nUnable to write SecurityTrails results: {exc}\n")
        return

    if subdomains:
        info("\nSecurityTrails Complete")
        info(f"\n{len(subdomains)} Subdomains discovered by SecurityTrails")
    else:
        warning("\nSecurityTrails returned no subdomains.\n")
    time.sleep(1)


def trigger_dragonjar_webhook():
    info("\n\nTriggering DragonJAR webhook \n")
    response = None
    try:
        response = requests.get(
            "https://n8n.dragonjar.co/webhook/recon",
            params={"d": domain},
            timeout=30,
        )
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = ""
        if response is not None:
            body = f" ({response.status_code}: {response.text})"
        warning(f"\nDragonJAR webhook returned an error: {exc}{body}\n")
    except requests.RequestException as exc:
        warning(f"\nDragonJAR webhook request failed: {exc}\n")
    else:
        info("\nDragonJAR webhook triggered successfully")
    time.sleep(1)


def generate_domain_extension_list():
    global aggregated_hosts
    info("\n\nGenerating domain extension list \n")
    response = None
    source_url = "https://raw.githubusercontent.com/DragonJAR/Scripts/master/all-domain-extensions.txt"
    try:
        response = requests.get(source_url, timeout=30)
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = ""
        if response is not None:
            body = f" ({response.status_code}: {response.text})"
        warning(f"\nUnable to download domain extension template: {exc}{body}\n")
        run_httpx_for_aggregated_hosts()
        return
    except requests.RequestException as exc:
        warning(f"\nRequest error while downloading domain extension template: {exc}\n")
        run_httpx_for_aggregated_hosts()
        return

    search_token = domain.split(".", 1)[0] if domain else ""
    replaced_content = re.sub(
        r"FUZZ", search_token, response.text, flags=re.IGNORECASE
    )
    output_file = "{}-extensions.txt".format(output_base)
    try:
        with open(output_file, "w") as handle:
            handle.write(replaced_content)
    except OSError as exc:
        error(f"\nUnable to write domain extension list: {exc}\n")
        run_httpx_for_aggregated_hosts()
        return

    total_entries = sum(1 for line in replaced_content.splitlines() if line.strip())
    info(f"\nDomain extension wordlist saved to {output_file}")
    info(f"\nTotal entries: {total_entries}")
    extension_hosts = {
        line.strip() for line in replaced_content.splitlines() if line.strip()
    }
    aggregated_hosts.update(extension_hosts)
    run_httpx_for_aggregated_hosts()
    time.sleep(1)


def check_gopath(cmd, install_repo):
    if os.environ["GOPATH"]:
        execs = os.listdir(os.path.join(os.environ["GOPATH"], "bin"))
    if cmd in execs:
        warning(
            "\nFound '{}' in your $GOPATH/bin folder please add this to your $PATH".format(
                cmd
            )
        )
    else:
        ans = input(
            "\n{}{} does not appear to be installed, would you like to run `go get -u -v {}`? [y/N]{}".format(
                colorama.Fore.RED, cmd, install_repo, colorama.Style.RESET_ALL
            )
        )

        if ans.lower() == "y":
            info("\nInstalling {}".format(install_repo))
            os.system("go get -u -v {}".format(install_repo))
            return True


def amass(rerun=0):
    if which("amass"):
        amassFileName = "{}_amass.txt".format(output_base)
        amassCmd = "amass enum -timeout 2 -d {} -o {}".format(domain, amassFileName)
        debug("\nRunning Command: {}".format(amassCmd))
        execute_tool(amassCmd, "Amass")
    else:
        warning("\n\namass is not currently in your $PATH \n")
        if check_gopath("amass", "github.com/OWASP/Amass/...") and rerun != 1:
            amass(rerun=1)


def subfinder(rerun=0):
    if which("subfinder"):
        subfinderFileName = "{}_subfinder.txt".format(output_base)
        subfinderCmd = "subfinder -d {} -o {}".format(domain, subfinderFileName)
        debug("\nRunning Command: {}".format(subfinderCmd))
        execute_tool(subfinderCmd, "Subfinder")
    else:
        warning("\n\nubfinder is not currently in your $PATH \n")
        if check_gopath("subfinder", "github.com/subfinder/subfinder") and rerun != 1:
            subfinder(rerun=1)


def eyewitness(filename):
    info("\n\nRunning EyeWitness  \n")
    EWHTTPScriptIPS = "eyewitness -f {} --no-prompt --web ".format(
        # os.path.join(script_path, "/usr/bin/eyewitness"),
        filename,
        "--active-scan" if active else "",
        output_base,
        time.strftime("%m-%d-%y-%H-%M"),
    )
    if vpn:
        info(
            "\nIf not connected to VPN manually run the following command on reconnect:\n{}".format(
                EWHTTPScriptIPS
            )
        )
        vpncheck()
    debug("\nRunning Command: {}".format(EWHTTPScriptIPS))
    os.system(EWHTTPScriptIPS)
    print("\a")


def writeFiles(name):
    """Writes info of all hosts from subhosts
    """
    subdomainCounter = 0
    subdomainAllFile = "{}-all.txt".format(output_base)
    fileExt = {
        "sublist3r": ".txt",
        "knock": ".txt",
        "enumall": ".lst",
        "massdns": ".txt",
        "amass": ".txt",
        "subfinder": ".txt",
        "shodan": ".txt",
        "securitytrails": ".txt",
    }
    fileName = output_base + "_" + name + fileExt[name]

    debug("\n Opening %s File" % name)
    if not os.path.exists(fileName):
        warning("\nNo results file found for {}. Skipping.\n".format(name))
        return subdomainCounter
    try:
        with open(fileName, "r") as f:
            SubHosts = f.read().splitlines()

        with open(subdomainAllFile, "a") as f:
            f.writelines("\n\n" + name)
            for hosts in SubHosts:
                hosts = "".join(hosts)
                f.writelines("\n" + hosts)
                subdomainCounter = subdomainCounter + 1
        os.remove(fileName)
        info("\n{} Subdomains discovered by {}".format(subdomainCounter, name))
    except Exception as exc:
        error("\nError processing {} results: {}\n".format(name, exc))
    return subdomainCounter


def subdomainfile():
    global aggregated_hosts, scope_file_path, output_dir
    subdomainAllFile = "{}-all.txt".format(output_base)
    # Ensure combined file exists before appending results from sources
    open(subdomainAllFile, "w").close()
    names = ["sublist3r", "knock", "enumall", "massdns", "amass", "subfinder"]
    if shodan_enabled and shodan_api_key:
        names.append("shodan")
    if securitytrails_enabled and securitytrails_api_key:
        names.append("securitytrails")

    for name in names:
        writeFiles(name)

    debug("\nCombining Domains Lists\n")
    unique_domains = set()
    with open(subdomainAllFile, "r") as domain_list:
        for raw_line in domain_list:
            candidate = raw_line.strip()
            if not candidate:
                continue
            if candidate.endswith(domain):
                unique_domains.add(candidate)

    sorted_domains = sorted(unique_domains)
    total_unique = len(sorted_domains)
    aggregated_hosts = set(sorted_domains)

    subdomainUniqueFile = "{}-unique.txt".format(output_base)
    with open(subdomainUniqueFile, "w") as outfile:
        for host in sorted_domains:
            outfile.write(f"{host}\n")

    scope_file = os.path.join(script_path, "scope.txt")
    try:
        with open(scope_file, "w") as scope_handle:
            for host in sorted_domains:
                scope_handle.write(f"{host}\n")
        scope_file_path = scope_file
        info(f"\nScope list saved to {scope_file}")
    except OSError as exc:
        scope_file_path = None
        error(f"\nUnable to write scope file: {exc}\n")

    eyewitnessTargetsFile = "{}-urls.txt".format(output_base)
    with open(eyewitnessTargetsFile, "w") as targets:
        for host in sorted_domains:
            targets.write(f"https://{host}\n")
            if ports is not False:
                targets.write(f"https://{host}:8443\n")
            if secure is False:
                targets.write(f"http://{host}\n")
                if ports is not False:
                    targets.write(f"http://{host}:8080\n")

    if total_unique:
        info(f"\nIdentified {total_unique} unique subdomains")
    else:
        warning("\nNo subdomains identified in combined results.\n")
    info(f"\nSubdomain list saved to {subdomainUniqueFile}")
    info(f"\nHTTP service targets saved to {eyewitnessTargetsFile}")

    if output_dir:
        combinar_path = os.path.join(output_dir, "combinar.txt")
        sinduplicados_path = os.path.join(output_dir, "sinduplicados.txt")
        # Remove previous aggregation artifacts to avoid self-inclusion
        for cleanup_path in (combinar_path, sinduplicados_path):
            if os.path.exists(cleanup_path):
                try:
                    os.remove(cleanup_path)
                except OSError as exc:
                    warning(f"\nUnable to remove {cleanup_path}: {exc}\n")
        txt_files = []
        try:
            for entry in sorted(os.listdir(output_dir)):
                if not entry.lower().endswith(".txt"):
                    continue
                if entry in ("combinar.txt", "sinduplicados.txt"):
                    continue
                txt_files.append(os.path.join(output_dir, entry))
        except OSError as exc:
            warning(f"\nUnable to list files in {output_dir}: {exc}\n")
            txt_files = []

        if txt_files:
            try:
                with open(combinar_path, "w") as combinado:
                    for file_path in txt_files:
                        try:
                            with open(file_path, "r") as source:
                                contents = source.read()
                        except OSError as exc:
                            warning(f"\nUnable to read {file_path}: {exc}\n")
                        else:
                            if not contents:
                                continue
                            combinado.write(contents)
                            if not contents.endswith("\n"):
                                combinado.write("\n")
                info(f"\nCombined text output saved to {combinar_path}")
            except OSError as exc:
                error(f"\nUnable to write combined output: {exc}\n")
            else:
                unique_entries = set()
                try:
                    with open(combinar_path, "r") as combinado:
                        for line in combinado:
                            cleaned = line.strip()
                            if cleaned:
                                unique_entries.add(cleaned)
                except OSError as exc:
                    error(f"\nUnable to read combined output for de-duplication: {exc}\n")
                else:
                    try:
                        with open(sinduplicados_path, "w") as unique_file:
                            for item in sorted(unique_entries):
                                unique_file.write(f"{item}\n")
                        info(f"\nUnique sorted output saved to {sinduplicados_path}")
                    except OSError as exc:
                        error(f"\nUnable to write unique output: {exc}\n")

    time.sleep(1)
    rootdomainStrip = domain.replace(".", "_")
    info("\nCleaning Up Old Files\n")
    if output_dir:
        cleanup_patterns = [domain, rootdomainStrip]
        for pattern in cleanup_patterns:
            pattern_glob = os.path.join(output_dir, pattern + "*")
            for match in glob.glob(pattern_glob):
                try:
                    if os.path.isfile(match):
                        os.remove(match)
                except OSError as exc:
                    warning(f"\nUnable to remove {match}: {exc}\n")
    if not noeyewitness:
        eyewitness(eyewitnessTargetsFile)


def vpncheck():
    vpnck = requests.get("https://ifconfig.co/json")
    # Change "City" to your city")
    if "City" in vpnck.text:
        warning("\nNot connected via VPN ")
        warning("\n{}".format(vpnck.content))
        warning("\nQuitting domained... ")
        quit()
    else:
        info("\nConnected via VPN ")
        info("\n{}".format(vpnck.content))
        time.sleep(5)


def notified():
    notifySub = "domained Script Finished"
    notifyMsg = "domained Script Finished for {}".format(domain)
    Config = configparser.ConfigParser()
    Config.read(os.path.join(script_path, "ext/notifycfg.ini"))
    if (Config.get("Pushover", "enable")) == "True":
        poToken = Config.get("Pushover", "token")
        poUser = Config.get("Pushover", "user")
        if "device" in Config.options("Pushover"):
            poDevice = Config.get("Pushover", "device")
            poRequestPayload = {
                "token": poToken,
                "user": poUser,
                "device": poDevice,
                "title": notifySub,
                "message": notifyMsg,
            }
        else:
            poRequestPayload = {
                "token": poToken,
                "user": poUser,
                "title": notifySub,
                "message": notifyMsg,
            }
            poValidatePayload = {"token": poToken, "user": poUser}
            poValidate = requests.post(
                "https://api.pushover.net/1/users/validate.json",
                data=(poValidatePayload),
            )
            poJsonV = poValidate.json()
            if poJsonV["status"] == 1:
                info("\nPushover Account Validated\n")
                poRequest = requests.post(
                    "https://api.pushover.net/1/messages.json", data=(poRequestPayload)
                )
                poJsonR = poRequest.json()
                if poJsonV["status"] == 1:
                    info("\nPushover Account Notified\n")
                else:
                    error("\nError - Pushover Account Not Notified\n")
            else:
                error("\nError - Pushover Account Not Validated\n")
    if (Config.get("Email", "enable")) == "True":
        gmailUser = Config.get("Email", "user")
        gmailPass = Config.get("Email", "password")
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(gmailUser, gmailPass)
            subject = "domained Script Complete"
            text = "domained Script Complete for " + domain
            msg = "Subject: {}\n\n{}".format(subject, text)
            server.sendmail(gmailUser, gmailUser, msg)
            server.quit()
            info("\nEmail Notification Sent\n")
        except:
            error("\nError - Email Notification Not Sent\n")


def options():
    global output_dir
    if vpn:
        vpncheck()
    if fresh:
        os.system("rm -r output")
        newpath = r"output"
        os.makedirs(newpath)
        if domain:
            output_dir = os.path.join(newpath, domain)
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as exc:
                error(f"\nUnable to create output directory {output_dir}: {exc}\n")
                output_dir = None
    if install or upgrade:
        upgradeFiles()
    else:
        if domain:
            if quick:
                amass()
                subfinder()
                shodan_subdomains()
                securitytrails_subdomains()
            elif bruteforce:
                massdns()
                sublist3r(True)
                enumall()
                amass()
                subfinder()
                shodan_subdomains()
                securitytrails_subdomains()
            else:
                sublist3r()
                enumall()
                knockpy(knock_timeout)
                amass()
                subfinder()
                shodan_subdomains()
                securitytrails_subdomains()
            subdomainfile()
            generate_domain_extension_list()
            trigger_dragonjar_webhook()
            if notify:
                notified()
        else:
            warning("\nPlease provide a domain. Ex. -d example.com")
    colored("\nAll your subdomain are belong to us", colorama.Fore.BLUE)


if __name__ == "__main__":
    banner()
    args = get_args()
    domain = args.domain
    if domain:
        output_dir = os.path.join("output", domain)
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            error(f"\nUnable to create output directory {output_dir}: {exc}\n")
            output_dir = None
    else:
        output_dir = None
    output_base = (
        os.path.join(output_dir, domain) if output_dir else os.path.join("output", "domained")
    )
    script_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_path, "ext/apicfg.ini")
    if os.path.exists(config_path):
        api_settings = configparser.ConfigParser()
        api_settings.read(config_path)
    else:
        api_settings = None

    shodan_enabled = False
    shodan_api_key = None
    if api_settings and api_settings.has_section("Shodan"):
        shodan_enabled = api_settings.getboolean("Shodan", "enable", fallback=False)
        shodan_api_key = api_settings.get("Shodan", "api_key", fallback="").strip()
        if not shodan_api_key:
            shodan_enabled = False
            debug("\nShodan API key missing. Skipping Shodan integration.\n")

    securitytrails_enabled = False
    securitytrails_api_key = None
    if api_settings and api_settings.has_section("SecurityTrails"):
        securitytrails_enabled = api_settings.getboolean(
            "SecurityTrails", "enable", fallback=False
        )
        securitytrails_api_key = api_settings.get(
            "SecurityTrails", "api_key", fallback=""
        ).strip()
        if not securitytrails_api_key:
            securitytrails_enabled = False
            debug("\nSecurityTrails API key missing. Skipping SecurityTrails integration.\n")

    secure = args.secure
    bruteforce = args.bruteforce
    upgrade = args.upgrade
    install = args.install
    ports = args.ports
    vpn = args.vpn
    quick = args.quick
    bruteall = args.bruteall
    fresh = args.fresh
    notify = args.notify
    active = args.active
    noeyewitness = args.noeyewitness
    knock_timeout = args.knock_timeout
    options()
