#!/bin/bash

echo -en "\033[37;1;41m Скрипт автоматической настройки IPv6 прокси. \033[0m \n\n\n"
echo -en "\033[37;1;41m Хостинг VPS серверов - VPSVille.ru \033[0m"
echo -en "\033[37;1;41m Сети IPv6 - /64, /48, /36, /32 под прокси. \033[0m \n\n"
echo ""

read -p "Нажмите [Enter] для продолжения..."

echo -e "Конфигурация IPv6 прокси \n"

echo "Введите выданную сеть и нажмите [ENTER]:"
read network

if [[ $network == *"::/48"* ]]
then
    mask=48
elif [[ $network == *"::/64"* ]]
then
    mask=64
elif [[ $network == *"::/32"* ]]
then
    mask=32
    echo "Введите сеть /64, это шлюз необходимый для подключения сети /32. Сеть /64 подключена в личном кабинете в разделе - Сеть."
    read network_mask
elif [[ $network == *"::/36"* ]]
then
    mask=36
    echo "Введите сеть /64, это шлюз необходимый для подключения сети /36. Сеть /64 подключена в личном кабинете в разделе - Сеть."
    read network_mask
else
    echo "Неопознанная маска или неверный формат сети, введите сеть с маской /64, /48, /36 или /32"
    exit 1
fi
echo "Введите количество адресов для случайной генерации"
read MAXCOUNT
THREADS_MAX=`sysctl kernel.threads-max|awk '{print $3}'`
MAXCOUNT_MIN=$(( MAXCOUNT-200 ))
if (( MAXCOUNT_MIN > THREADS_MAX )); then
    echo "kernel.threads-max = $THREADS_MAX этого недостаточно для указанного количества адресов!"
fi

echo "Введите логин для прокси"
read proxy_login
echo "Введите пароль для прокси"
read proxy_pass
echo "Введите начальный порт для прокси"
read proxy_port

base_net=`echo $network | awk -F/ '{print $1}'`
base_net1=`echo $network_mask | awk -F/ '{print $1}'`

timerrotation () {
        echo "Введите частоту ротации в минутах (1-59)"
                read timer
                        if [[ $timer -ge 1 ]] && [[ $timer -le 59 ]];
                                then echo "Ротация каждые $timer минут."
                                else echo "Укажите число в диапазоне между 1 и 59"
                                        timerrotation
                        fi   }

startrotation () {
echo "Использовать ротацию? [Y/N]"
read rotation
if [[ "$rotation" != [yY] ]] && [[ "$rotation" != [nN] ]];
then
        echo "Неккоректно введенные данные"
                startrotation
else
        if [[ "$rotation" != [Yy] ]];
                then echo "Вы отказались от использования ротации"
                else echo "Вы будете использовать ротацию"
                        timerrotation
        fi
fi   }

startrotation

echo "Настройка прокси для сети $base_net с маской $mask"
sleep 2
echo "Настройка базового IPv6 адреса"
ip -6 addr add ${base_net}2 peer ${base_net}1 dev eth0
sleep 5
ip -6 route add default via ${base_net}1 dev eth0
ip -6 route add local ${base_net}/${mask} dev lo


if [ -f /root/3proxy.tar ]; then
   echo "Архив 3proxy.tar уже скачан, продолжаем настройку..."
else
   echo "Архив 3proxy.tar отсутствует, скачиваем..."
   wget --no-check-certificate https://blog.vpsville.ru/uploads/3proxy.tar; tar -xvf 3proxy.tar
fi

if [ -f /root/ndppd.tar ]; then
   echo "Архив ndppd.tar уже скачан, продолжаем настройку..."
else
   echo "Архив ndppd.tar отсутствует, скачиваем..."
   wget --no-check-certificate https://blog.vpsville.ru/uploads/ndppd.tar; tar -xvf ndppd.tar
fi

if [ -f /root/3proxy/3proxy.cfg ];
	then echo "Обнаружен конфиг 3proxy.cfg. Удаляем."
		cat /dev/null > /root/3proxy/3proxy.cfg
	 	cat /dev/null > /root/3proxy/3proxy.sh
		cat /dev/null > /root/3proxy/random.sh
		cat /dev/null > /root/3proxy/rotate.sh
		cat /dev/null > /etc/rc.local
		cat /dev/null > /var/spool/cron/crontabs/root
	else echo "Конфиг 3proxy.cfg отсутствует. Первичная настройка."
fi



echo "Конфигурирование ndppd"
mkdir -p /root/ndppd/
rm -f /root/ndppd/ndppd.conf
cat >/root/ndppd/ndppd.conf <<EOL
route-ttl 30000
proxy eth0 {
   router no
   timeout 500
   ttl 30000
   rule __NETWORK__ {
      static
   }
}
EOL
sed -i "s/__NETWORK__/${base_net}\/${mask}/" /root/ndppd/ndppd.conf

echo "Конфигурирование 3proxy"
rm -f /root/ip.list
echo "Генерация $MAXCOUNT адресов "
array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
count=1
first_blocks=`echo $base_net|awk -F:: '{print $1}'`
rnd_ip_block ()
{
    a=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    b=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    c=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    d=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    if [[ "x"$mask == "x48" ]]
    then
        e=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        echo $first_blocks:$a:$b:$c:$d:$e >> /root/ip.list
    elif [[ "x"$mask == "x32" ]]
    then
        e=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        f=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        echo $first_blocks:$a:$b:$c:$d:$e:$f >> /root/ip.list
    elif [[ "x"$mask == "x36" ]]
    then
        num_dots=`echo $first_blocks | awk -F":" '{print NF-1}'`
        if [[ x"$num_dots" == "x1" ]]
        then
            #first block
            block_num="0"
            first_blocks_cut=`echo $first_blocks`
        else
            #2+ block
            block_num=`echo $first_blocks | awk -F':' '{print $NF}'`
            block_num="${block_num:0:1}"
            first_blocks_cut=`echo $first_blocks | awk -F':' '{print $1":"$2}'`
        fi
        a=${block_num}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        e=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        f=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        echo $first_blocks_cut:$a:$b:$c:$d:$e:$f >> /root/ip.list
    else
        echo $first_blocks:$a:$b:$c:$d >> /root/ip.list
    fi
}
while [ "$count" -le $MAXCOUNT ]
do
        rnd_ip_block
        let "count += 1"
done
echo "Генерация конфига 3proxy"
mkdir -p /root/3proxy
rm /root/3proxy/3proxy.cfg
cat >/root/3proxy/3proxy.cfg <<EOL
#!/bin/bash

daemon
maxconn 10000
nserver 127.0.0.1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
stacksize 6000
flush
auth strong
users ${proxy_login}:CL:${proxy_pass}
allow ${proxy_login}
EOL

echo >> /root/3proxy/3proxy.cfg
ip4_addr=`ip -4 addr sh dev eth0|grep inet |awk '{print $2}'`
port=${proxy_port}
count=1
for i in `cat /root/ip.list`; do
    echo "proxy -6 -s0 -n -a -p$port -i$ip4_addr -e$i" >> /root/3proxy/3proxy.cfg
    ((port+=1))
    ((count+=1))
done

if grep -q "net.ipv6.ip_nonlocal_bind=1" /etc/sysctl.conf;
then
   echo "Все параметры в sysctl уже были установлены"
else
   echo "Конфигурирование sysctl"
   echo "net.ipv6.conf.eth0.proxy_ndp=1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.all.proxy_ndp=1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
   echo "net.ipv6.ip_nonlocal_bind=1" >> /etc/sysctl.conf
   echo "vm.max_map_count=195120" >> /etc/sysctl.conf
   echo "kernel.pid_max=195120" >> /etc/sysctl.conf
   echo "net.ipv4.ip_local_port_range=1024 65000" >> /etc/sysctl.conf
   sysctl -p
fi

ip4address=$(hostname -i)
echo "Создания файла с данными для подключения - $ip4address.list"
proxyport1=$(($proxy_port - 1 ))
touch -f /root/$ip4address.list
for ((i=0; i < $MAXCOUNT; i++)); do
proxyport1=$(($proxyport1 + 1))
echo "$ip4address:$proxyport1@$proxy_login:$proxy_pass" >> /root/$ip4address.list
done

echo "Конфигурирование systemd"
sed -i 's/#DefaultTasksMax=.*/DefaultTasksMax=30000/' /etc/systemd/system.conf


echo "Конфигурирование rc.local"
rm /etc/rc.local

if [ "$mask" = "64" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net}2 peer ${base_net}1 dev eth0" >> /etc/rc.local
echo "sleep 5" >> /etc/rc.local
echo "ip -6 route add default via ${base_net}1 dev eth0" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

if [ "$mask" = "48" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net}2 peer ${base_net}1 dev eth0" >> /etc/rc.local
echo "sleep 5" >> /etc/rc.local
echo "ip -6 route add default via ${base_net}1 dev eth0" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

if [ "$mask" = "36" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net1}2/64 dev eth0" >> /etc/rc.local
echo "ip -6 route add default via ${base_net1}1" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

if [ "$mask" = "32" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net1}2/64 dev eth0" >> /etc/rc.local
echo "ip -6 route add default via ${base_net1}1" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

echo "Создаем службу 3proxy.service"
cat > /etc/systemd/system/3proxy.service << EOF
[Unit]
Description=3proxy proxy Server
[Service]
Type=forking
ExecStart=/root/3proxy/bin/3proxy /root/3proxy/3proxy.cfg
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable 3proxy.service
systemctl start 3proxy.service

if [[ "$rotation" != [yY] ]];
	then echo "Deny rotation"
	else
cat > /root/3proxy/3proxy.sh << EOF
#!/bin/bash

echo daemon
echo maxconn 10000
echo nscache 65536
echo timeouts 1 5 30 60 180 1800 15 60
echo setgid 65535
echo setuid 65535
echo flush
echo auth strong
echo users $proxy_login:CL:$proxy_pass
echo allow $proxy_login

ip4_addr=\$(ip -4 addr sh dev eth0|grep inet |awk '{print \$2}')
port=$proxy_port
count=1
for i in \$(cat /root/3proxy/ip.list); do
    echo "proxy -6 -n -a -p\$port -i\$ip4_addr -e\$i"
    ((port+=1))
    ((count+=1))
    if [ \$count -eq 10001 ]; then
        exit
    fi
done
EOF

chmod +x /root/3proxy/3proxy.sh

echo "Создаю random.sh"
network=${base_net%::*}
cat > /root/3proxy/random.sh << EOF
#!/bin/bash
mask=$mask
array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
MAXCOUNT=$MAXCOUNT
count=1
network=${base_net%::*}
rnd_ip_block ()
{
  b=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
  c=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
  d=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
  e=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
  f=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
 if [[ "\$mask" = "64" && "\$mask" = "48" && "\$mask" = "32" ]]; then
    a=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
 else
num_dots=`echo \$network | awk -F":" '{print NF-1}'`
if [[ x"\$num_dots" == "x1" ]]
        then
            #first block
            block_num="0"
            first_blocks_cut=`echo $network`
        else
            #2+ block
            block_num=`echo $network | awk -F':' '{print $NF}'`
            block_num="\${block_num:0:1}"
            first_blocks_cut=`echo $network | awk -F':' '{print $1":"$2}'`
fi
 a=\${block_num}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
 fi
if [[ "\$mask" = "64" ]]; then
  echo \$network:\$a:\$b:\$c:\$d
elif [[ "\$mask" = "48" ]]; then
  echo \$network:\$a:\$b:\$c:\$d:\$e
elif [[  "\$mask" = "32" ]]; then
  echo \$network:\$a:\$b:\$c:\$d:\$e:\$f
else
  echo \$first_blocks_cut:\$a:\$b:\$c:\$d:\$e:\$f

fi
}

while [ "\$count" -le \$MAXCOUNT ]
do
        rnd_ip_block
        let "count += 1"
        done
EOF

echo "Создал random.sh, возможно"
chmod +x /root/3proxy/random.sh

cat > /root/3proxy/rotate.sh << EOF
#!/bin/bash

/root/3proxy/random.sh > /root/3proxy/ip.list
/root/3proxy/3proxy.sh > /root/3proxy/3proxy.cfg
systemctl restart 3proxy

EOF

chmod +x /root/3proxy/rotate.sh

touch /var/spool/cron/crontabs/root
echo "*/$timer * * * * /bin/bash /root/3proxy/rotate.sh" >> /var/spool/cron/crontabs/root

fi
echo -en "\033[37;1;41m Конфигурация завершена, необходима перезагрузка \033[0m"
exit 0

