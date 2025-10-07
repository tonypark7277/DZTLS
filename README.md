## 1. DZTLS kernel installation

Install DZTLS custom kernel for generating and validating custom TFO cookie

``` bash
cd DZTLS_kernel
sudo apt-get -y install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison dwarves zstd

cp -v /boot/config-$(uname -r) ./.config 

make menuconfig

scripts/config --disable SYSTEM_TRUSTED_KEYS 
scripts/config --disable SYSTEM_REVOCATION_KEYS

make
make modules
sudo make modules_install
sudo make install
```

[Optional] After installation of DZTLS kernel, make sure that ubuntu is booted with our custom linux kernel `5.17.18+`

``` bash
sudo nano /etc/default/grub  # update GRUB_DEFAULT
sudo update-grub
sudo reboot
```

## 2. Systemd version upgrade (client side)

As mentioned in ZTLS, EDNS0 related bug existed in systemd until `v251-rc1`. We recommand to install or update systemd with higher version

## 3. ZTLSlib installation

==**Make sure that you install ztlslib after kernel build and systemd update**==

ZTLSlib is custom openssl library for 0-RTT data transmission without resumption.

``` bash
git clone https://github.com/swlim02/ztlslib
cd ztlslib

# configure installation
./Configure linux-x86_64 shared no-md2 no-mdc2 no-rc5 no-rc4 --prefix=/usr/local

# installing
make depend && make
sudo make install
```

## 4. DNS setting

For DZTLS to work in purpose, 2 following conditions are required.
1. Proper TXT and TLSA record should be set.
2. DNS server should support DNS cookie

### 4-1) DNS zone file setting

DZTLS's TXT record and TLSA record replace `ServerHello` as in [ztls](https://github.com/swlim02/ztls) of swlim

We post example DNS zone file for DZTLS and sementics for each record in `example DNS zone file for DSZLS`.
For more detailed information about sementics, please refer to 'ZTLS: A DNS-based Approach to Zero Round Trip Delay in TLS handshake' published in THE WEB CONFERENCE 2023.

### 4-2) DNS cookie setting

[ghjeong] 이 부분만 채워주세요.

## 5. DZTLS execution

Make sure that before executing server or client program, execute following command.
``` bash
export LD_LIBRARY_PATH=/usr/local/lib
```

### 5-1) DZTLS server setting
``` bash
cd DZTLS

sudo sysctl net.ipv4.tcp_fastopen=3 # Turn on TCP Fast Open

make server
export LD_LIBRARY_PATH=/usr/local/lib
./server [port number]
```

### 5-2) DZTLS client setting
``` bash
cd DZTLS

sudo sysctl net.ipv4.tcp_fastopen=3 # Turn on TCP Fast Open
```

Before compoile, change IP address hardcoded in `create_socket_bio()` to your own IP address in little endian.
> uint64_t temp = 0xc4f6c92b; (43.201.246.196 -> 0x2b c9 f6 c4)


``` bash
make all
export LD_LIBRARY_PATH=/usr/local/lib
./[TLS mode]_[TCP mode][_getdns]_client [domain name] [port]
```

> [TLS mode] = ztls | tls
> [TCP mode] = tfo  | tcp


## 6. QUIC experiment

1. Server certificate generation

``` bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/key.pem -out certs/cert.pem -days 365 \
  -subj "/CN=example.com“
```

2. Build

``` bash
sudo apt update
sudo apt install python3.8-venv

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install aioquic
```

3. Operate server

``` bash
# with SAV
python server.py —sav
# without SAV
python server.py —no-sav
```

4. Operate client

``` bash
# change the server IP in the code
python client.py 
```

5. Operate shell
``` bash
chmod +x run.sh
./run.sh 100 sav_on
./run.sh 100 sav_offk
```
