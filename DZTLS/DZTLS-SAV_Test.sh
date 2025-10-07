#!/bin/bash

port=12345

if [ "$#" -ne 3 ]; then
    echo "$# is Illegal number of parameters."
    echo "Usage: $0 [server_country] [DNS_resolver] [num_test]"
	exit 1
fi

args=$@
server_country=$1;
resolver=$2;
num_test=$3;
domain_name="${server_country}.aztls.com"
echo $domain_name

## check directory ./result/$server_country exitst
## if doesn't exist, make directory
if [ ! -d "./result/${server_country}_${resolver}/" ]; then
    echo "Directory doesn't exists. Make one"
    mkdir -p ./result/${server_country}_${resolver}
fi

c=1
while [ "$c" -le "$num_test" ]
do
    formatted_test_num=$(printf "%03d" "$c");
    echo "$formatted_test_num-th test begin"
    # echo "$c th test start = $c" > ./result/Ohio/Ohio_$formatted_test_num.txt;
    sudo ./ztls_tfo_getdns_client $domain_name $port > ./result/${server_country}_${resolver}/ztls_tfo_$formatted_test_num.txt;
    sleep 1
    # sudo ./ztls_tcp_getdns_client $domain_name $port > ./result/${server_country}_${resolver}/ztls_tcp_$formatted_test_num.txt;
    # sleep 1
    sudo ./tls_tcp_getdns_client $domain_name $port > ./result/${server_country}_${resolver}/tls_tcp_$formatted_test_num.txt;
    sleep 1
    c=$(expr $c + 1)
    #sudo python3 temp.py > ./result/$server_country/$formatted_test_num.txt
done

# sudo python3 stats.py tls_tcp  $server_country $resolver $num_test
# sudo python3 stats.py ztls_tcp $server_country $resolver $num_test
# sudo python3 stats.py ztls_tfo $server_country $resolver $num_test
