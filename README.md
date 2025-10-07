## 1. DZTLS kernel install

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

aztlslib is specialized version of [ztlslib](https://github.com/swlim02/ztlslib) of swlim for page load time experiment.
If page load time experiment for aztls is not required, just install [ztlslib](https://github.com/swlim02/ztlslib)

ZTLSlib : https://github.com/swlim02/ztlslib

==**Make sure that you install ztlslib after kernel build and systemd update**==


``` bash
git clone https://github.com/swlim02/ztlslib
cd ztlslib

# configure installation
./Configure linux-x86_64 shared no-md2 no-mdc2 no-rc5 no-rc4 --prefix=/usr/local

# installing
make depend && make
sudo make install
```

## 4. DZTLS execution

Make sure that before executing server or client program, execute following command.
``` bash
export LD_LIBRARY_PATH=/usr/local/lib
```

### 4-1) DZTLS server setting
``` bash
cd DZTLS

sudo sysctl net.ipv4.tcp_fastopen=3 # Turn on TCP Fast Open

make server
export LD_LIBRARY_PATH=/usr/local/lib
./server [port number]
```

### 4-2) DZTLS client setting
``` bash
cd DZTLS

sudo sysctl net.ipv4.tcp_fastopen=3 # Turn on TCP Fast Open
```

Change IP address hardcoded in `create_socket_bio()` to your own IP address in little endian.
> uint64_t temp = 0xc4f6c92b; (43.201.246.196 -> 0x2b c9 f6 c4)

``` bash
make all
export LD_LIBRARY_PATH=/usr/local/lib
./[TLS mode]_[TCP mode][_getdns]_client [domain name] [port]
```

> [TLS mode] = ztls | tls
> [TCP mode] = tfo  | tcp
