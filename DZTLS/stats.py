import csv
import sys
import statistics

def ztls_tfo_stats(mode, num_record, country, resolver, num_test):
    inputs = "./result/" + country + "_" + resolver + "/"
    outputs = "./result/" + country + "_" + resolver +"/{}_{}_{}.csv".format(country, resolver, mode)
    csvfile_out = open(outputs, 'w', newline='', encoding='utf-8')
    writer = csv.writer(csvfile_out)
    
    result = [[0]*num_test for _ in range(num_record + 1)]
    legend = ["", "A record", "TXT record", "TLSA record", "First Response Time"] if num_record == 4 else ["", "A record", "First Response Time"]
    writer.writerow(legend)
    for i in range(num_test):
        infile = inputs + "{0}_{1:0>3}.txt".format(mode, i+1)
        res = processing_tls(infile) if num_record == 2 else processing_ztls(infile)
        print(res)
        writer.writerow([i] + res)
        for j in range(num_record):
            result[j+1][i] = res[j]
        result[0][i] = i+1
    mean = ['mean'] + [statistics.mean(result[i+1]) for i in range(num_record)]
    median = ['median'] + [statistics.median(result[i+1]) for i in range(num_record)]
    writer.writerow(mean)
    writer.writerow(median)
    csvfile_out.close()

def processing_tls(infile):
    print(infile)
    file_in = open(infile, 'r', newline = '', encoding='utf-8')
    start_FR, start_A = 0, 0
    end_FR, end_A = 0, 0
    for row in file_in:
        if row.startswith("start :"):
            start_FR = float(row.split()[-1])*1000
        elif row.startswith("start A and AAAA DNS records query"):
            start_A = float(row.split()[-1])*1000
        elif row.startswith("complete A and AAAA DNS records query"):
            end_A = float(row.split()[-1])*1000
        elif row.startswith("receiving application data from server :"):
            end_FR = float(row.split()[-1])*1000
    file_in.close()
    return [end_A - start_A, end_FR - start_FR]


def processing_ztls(infile):
    print(infile)
    file_in = open(infile, 'r', newline = '', encoding='utf-8')
    start_FR, start_A, start_TXT, start_TLSA = 0, 0, 0, 0
    end_FR, end_A, end_TXT, end_TLSA = 0, 0, 0, 0
    for row in file_in:
        if row.startswith("start :"):
            start_FR = float(row.split()[-1])*1000
        elif row.startswith("start A and AAAA DNS records query"):
            start_A = float(row.split()[-1])*1000
        elif row.startswith("start DNS TXT query"):
            start_TXT = float(row.split()[-1])*1000
        elif row.startswith("start DNS TLSA query"):
            start_TLSA = float(row.split()[-1])*1000
        elif row.find("complete A and AAAA DNS records query") >= 0:
            end_A = float(row.split()[-1])*1000
        elif row.startswith("complete DNS TXT query"):
            end_TXT = float(row.split()[-1])*1000
        elif row.startswith("complete DNS TLSA query"):
            end_TLSA = float(row.split()[-1])*1000
        elif row.startswith("receiving application data from server : mmlab"):
            end_FR = float(row.split()[-1])*1000
    file_in.close()
    return [end_A - start_A, end_TXT - start_TXT, end_TLSA - start_TLSA, end_FR - start_FR]

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: python3 stats.py [mode] [server_country] [resolver] [num_test]")
        print("       [mode] = tls_tcp | ztls_tcp")
        print("       [server_country] = tokyo | singapore | ohio")
        print("       [resolver] = stub | local | global")
        exit()
    mode = sys.argv[1]
    country = sys.argv[2]
    resolver = sys.argv[3]
    num_test = int(sys.argv[4])
    num_record = 2 if mode == "tls_tcp" else 4
    ztls_tfo_stats(mode, num_record, country, resolver, num_test)
