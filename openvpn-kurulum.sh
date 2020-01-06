#!/bin/bash

if grep -qs "14.04" /etc/os-release; then
	echo "Ubuntu 14.04 desteklenmiyor"
	exit
fi

if grep -qs "jessie" /etc/os-release; then
	echo "Debian 8 is çok eski ve desteklenmiyor"
	exit
fi

if grep -qs "CentOS release 6" /etc/redhat-release; then
	echo "CentOS 6 çok eski ve desteklenmiyor"
	exit
fi

if grep -qs "Ubuntu 16.04" /etc/os-release; then
	echo "Ubuntu 16.04 çok eski ve desteklenmiyor"
	exit
fi

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "İşlemi root olarak yapınız!"
	exit
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "TUN aygıtı açık değil!
TUN aygıtını açtıktan sonra tekrar deneyin!"
	exit
fi

if ! iptables -t nat -nL &>/dev/null; then
	echo "iptables/netfilter NAT tabloları eklenemedi.
Sisteminizde iptables / netfilter bulunduğundan emin olun.
OpenVZ kullanıyorsanız, sağlayıcınızdan tam netfilter desteğini etkinleştirmesini isteyin."
	exit
fi

if [[ -e /etc/debian_version ]]; then
	os="debian"
	group_name="nogroup"
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	os="centos"
	group_name="nobody"
else
	echo "Görünüşe göre bu yükleyiciyi Debian, Ubuntu veya CentOS'ta çalıştırmıyorsunuz"
	exit
fi

new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$1".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$1".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$1".ovpn
}

if [[ -e /etc/openvpn/server/server.conf ]]; then
	while :
	do
	clear
		echo "OpenVPN servisi kurulmuş."
		echo
		echo "Ne yapmak istiyorsunuz?"
		echo "   1) Yeni bir kullanıcı ekle"
		echo "   2) Varolan bir kullanıcıyı iptal et"
		echo "   3) OpenVPN servisini kaldır"
		echo "   4) Çıkış"
		read -p "Bir seçenek seçin: " option
		until [[ "$option" =~ ^[1-4]$ ]]; do
			echo "$option: geçersiz seçim."
			read -p "Bir seçenek seçin: " option
		done
		case "$option" in
			1) 
			echo
			echo "İstemci sertifikasına bir ad verin."
			read -p "İstemci adı: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: geçersiz istemci adı."
				read -p "İstemci adı: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
			new_client "$client"
			echo
			echo " $client istemcisi eklendi, konfigürasyon dosyası burada:" ~/"$client.ovpn"
			exit
			;;
			2)
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "Mevcut istemciniz yok!"
				exit
			fi
			echo
			echo "İptal etmek istediğiniz mevcut istemci sertifikasını seçin:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Bir seçenek seçin: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Bir seçenek seçin: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Bu istemciyi iptal etmek istiyor musunuz $client? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: geçersiz seçim."
				read -p "Bu istemciyi iptal etmek istiyor musunuz $client? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f pki/reqs/"$client".req
				rm -f pki/private/"$client".key
				rm -f pki/issued/"$client".crt
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client istemcisi iptal edildi!"
			else
				echo
				echo "$client istemcisi iptal edildi!"
			fi
			exit
			;;
			3) 
			echo
			read -p "OpenVPN servisini kaldırmak istiyor musunuz? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: geçersiz seçim."
				read -p "OpenVPN servisini kaldırmak istiyor musunuz? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -rf /etc/openvpn/server
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				if [[ "$os" = "debian" ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				echo
				echo "OpenVPN servisi kaldırıldı!"
			else
				echo
				echo "Kaldırma iptal edildi!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo "OpenVPN kurulumuna hoş geldiniz!"
	echo
	echo "Varsayılan seçenekleri kullanmak için enter tuşuna basmanız yeter."
	if [[ $(ip addr | grep inet | grep -v inet6 | grep -vEc '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') -eq 1 ]]; then
		ip=$(ip addr | grep inet | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	else
		number_of_ips=$(ip addr | grep inet | grep -v inet6 | grep -vEc '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
		echo
		echo "OpenVPN servisi hangi IPv4 adresine bağlanmalıdır.?"
		ip addr | grep inet | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | nl -s ') '
		read -p "IPv4 adresi [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ips" ]]; do
			echo "$ip_number: geçersiz seçim."
			read -p "IPv4 adresi [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip addr | grep inet | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed -n "$ip_number"p)
	fi
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Bu sunucu NAT'ın arkasında. Genel IPv4 adresi veya anabilgisayar adı nedir?"
		get_public_ip=$(wget -4qO- "http://whatismyip.akamai.com/" || curl -4Ls "http://whatismyip.akamai.com/")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		[ -z "$public_ip" ] && public_ip="$get_public_ip"
	fi
	echo
	echo "OpenVPN bağlantıları için hangi protokolü istiyorsunuz?"
	echo "   1) UDP (önerilir)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: geçersiz seçim."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "OpenVPN hangi portu dinlesin?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: geçersiz seçim."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Hangi DNS servini kullanmak istersiniz?"
	echo "   1) Mevcut sistem ayarları"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-5]$ ]]; do
		echo "$dns: geçersiz seçim."
		read -p "DNS [1]: " dns
	done
	echo
	echo "İstemci sertifikanız için Türkçe karakter içermeyen bir ad yazın"
	read -p "İstemci adı [client]: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN kurulum için hazır."
	read -n1 -r -p "Devam etmek için herhangi bir tuşa basınız..."
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.5/EasyRSA-nix-3.0.5.tgz'
	wget -O ~/easyrsa.tgz "$easy_rsa_url" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$easy_rsa_url"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-3.0.5/ /etc/openvpn/server/
	mv /etc/openvpn/server/EasyRSA-3.0.5/ /etc/openvpn/server/easy-rsa/
	chown -R root:root /etc/openvpn/server/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/server/easy-rsa/
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			resolv_conf="/run/systemd/resolve/resolv.conf"
		else
			resolv_conf="/etc/resolv.conf"
		fi
		grep -v '#' "$resolv_conf" | grep nameserver | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
	else
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=/sbin/iptables -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=/sbin/iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=/sbin/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/sbin/iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=/sbin/iptables -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		if ! hash semanage 2>/dev/null; then
			if grep -qs "CentOS Linux release 7" "/etc/centos-release"; then
				yum install policycoreutils-python -y
			else
				yum install policycoreutils-python-utils -y
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	if [[ "$public_ip" != "" ]]; then
		ip="$public_ip"
	fi
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	systemctl enable --now openvpn-server@server.service
	new_client "$client"
	echo
	echo "Bitti!"
	echo
	echo "İstemci konfigürasyon dosyası burada:" ~/"$client.ovpn"
	echo "Daha fazla istemci istiyorsanız betiği tekrar çalıştırın!"
fi
