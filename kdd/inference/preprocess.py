import numpy as np
import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder


# normalize
def encode_numeric_zscore(df, name):
    with open("kdd/inference/normalize/" + name + ".pkl", "rb") as f:
        mean, sd = pickle.load(f)
    df[name] = (df[name] - mean) / sd


# label encoding
def encode_text_dummy(df, name):
    with open("kdd/inference/encoder/" + name + "_encoder.pkl", "rb") as f:
        encoder = pickle.load(f)
    df[name] = encoder.transform(df[name])


def read_data(path):
    data = pd.read_csv(path, header=None)
    data.columns = [
        "duration",  # 持续时间，范围是 [0, 58329]
        "protocol_type",  # 协议类型，三种：TCP, UDP, ICMP
        "service",  # 目标主机的网络服务类型，共有70种，如‘http_443′,‘imap4′等
        "flag",  # 连接正常或错误的状态，离散类型，共11种，如‘S0′,‘S1′,‘S2′等
        "src_bytes",  # 从源主机到目标主机的数据的字节数，范围是 [0,1379963888]
        "dst_bytes",  # 从目标主机到源主机的数据的字节数，范围是 [0.1309937401]
        "land",  # 若连接来自/送达同一个主机/端口则为1，否则为0
        "wrong_fragment",  # 错误分段的数量，连续类型，范围是[0,3]
        "urgent",  # 加急包的个数，连续类型，范围是[0,14]
        "count",  # 过去两秒内，与当前连接具有相同的目标主机的连接数，范围是[0,511]
        "srv_count",  # 过去两秒内，与当前连接具有相同服务的连接数，范围是[0,511]
        "serror_rate",  # 过去两秒内，在与当前连接具有相同目标主机的连接中，出现“SYN” 错误的连接的百分比，范围是[0.00,1.00]
        "srv_serror_rate",  # 过去两秒内，在与当前连接具有相同服务的连接中，出现“SYN” 错误的连接的百分比，范围是[0.00,1.00]
        "rerror_rate",  # 过去两秒内，在与当前连接具有相同目标主机的连接中，出现“REJ” 错误的连接的百分比，范围是[0.00,1.00]
        "srv_rerror_rate",  # 过去两秒内，在与当前连接具有相同服务的连接中，出现“REJ” 错误的连接的百分比，范围是[0.00,1.00]
        "same_srv_rate",  # 过去两秒内，在与当前连接具有相同目标主机的连接中，与当前连接具有相同服务的连接的百分比，范围是[0.00,1.00]
        "diff_srv_rate",  # 过去两秒内，在与当前连接具有相同目标主机的连接中，与当前连接具有不同服务的连接的百分比，范围是[0.00,1.00]
        "srv_diff_host_rate",  # 过去两秒内，在与当前连接具有相同服务的连接中，与当前连接具有不同目标主机的连接的百分比，范围是[0.00,1.00]
        "dst_host_count",  # 前100个连接中，与当前连接具有相同目标主机的连接数，范围是[0,255]
        "dst_host_srv_count",  # 前100个连接中，与当前连接具有相同目标主机相同服务的连接数，范围是[0,255]
        "dst_host_same_srv_rate",  # 前100个连接中，与当前连接具有相同目标主机相同服务的连接所占的百分比，范围是[0.00,1.00]
        "dst_host_diff_srv_rate",  # 前100个连接中，与当前连接具有相同目标主机不同服务的连接所占的百分比，范围是[0.00,1.00]
        "dst_host_same_src_port_rate",  # 前100个连接中，与当前连接具有相同目标主机相同源端口的连接所占的百分比，范围是[0.00,1.00]
        "dst_host_srv_diff_host_rate",  # 前100个连接中，与当前连接具有相同目标主机相同服务的连接中，与当前连接具有不同源主机的连接所占的百分比，范围是[0.00,1.00]
        "dst_host_serror_rate",  # 前100个连接中，与当前连接具有相同目标主机的连接中，出现SYN错误的连接所占的百分比，范围是[0.00,1.00]
        "dst_host_srv_serror_rate",  # 前100个连接中，与当前连接具有相同目标主机相同服务的连接中，出现SYN错误的连接所占的百分比，范围是[0.00,1.00]
        "dst_host_rerror_rate",  # dst_host_rerror_rate. 前100个连接中，与当前连接具有相同目标主机的连接中，出现REJ错误的连接所占的百分比，范围是[0.00,1.00]
        "dst_host_srv_rerror_rate",  # 前100个连接中，与当前连接具有相同目标主机相同服务的连接中，出现REJ错误的连接所占的百分比，范围是[0.00,1.00]
    ]

    #delete the invaild services

    valid_services = ['uucp_path', 'uucp', 'supdup', 'whois', 'nnsp', 'pm_dump', 'tftp_u', 'tim_i', 'netbios_ssn', 'link', 'remote_job', 'shell', 'red_i', 'iso_tsap', 'other', 'Z39_50', 'eco_i', 'auth', 'ftp', 'finger', 'pop_3', 'daytime', 'nntp', 'X11', 'netbios_dgm', 'http_443', 'ldap', 'rje', 'ctf', 'discard', 'systat', 'netbios_ns', 'urh_i', 'ntp_u', 'hostnames', 'smtp', 'echo', 'name', 'courier', 'sql_net', 'IRC', 'urp_i', 'telnet', 'bgp', 'time', 'exec', 'mtp', 'ftp_data', 'domain', 'login', 'ssh', 'klogin', 'private', 'efs', 'pop_2', 'sunrpc', 'ecr_i', 'domain_u', 'vmnet', 'http', 'printer', 'csnet_ns', 'gopher', 'imap4', 'kshell', 'netstat']

    data = data[data["service"].isin(valid_services)]

   


    



    # 对每一项数据进行相应处理
    encode_numeric_zscore(data, "duration")
    encode_text_dummy(data, "protocol_type")
    encode_text_dummy(data, "service")
    encode_text_dummy(data, "flag")
    encode_numeric_zscore(data, "src_bytes")
    encode_numeric_zscore(data, "dst_bytes")
    encode_text_dummy(data, "land")
    encode_numeric_zscore(data, "wrong_fragment")
    encode_numeric_zscore(data, "urgent")
    encode_numeric_zscore(data, "count")
    encode_numeric_zscore(data, "srv_count")
    encode_numeric_zscore(data, "serror_rate")
    encode_numeric_zscore(data, "srv_serror_rate")
    encode_numeric_zscore(data, "rerror_rate")
    encode_numeric_zscore(data, "srv_rerror_rate")
    encode_numeric_zscore(data, "same_srv_rate")
    encode_numeric_zscore(data, "diff_srv_rate")
    encode_numeric_zscore(data, "srv_diff_host_rate")
    encode_numeric_zscore(data, "dst_host_count")
    encode_numeric_zscore(data, "dst_host_srv_count")
    encode_numeric_zscore(data, "dst_host_same_srv_rate")
    encode_numeric_zscore(data, "dst_host_diff_srv_rate")
    encode_numeric_zscore(data, "dst_host_same_src_port_rate")
    encode_numeric_zscore(data, "dst_host_srv_diff_host_rate")
    encode_numeric_zscore(data, "dst_host_serror_rate")
    encode_numeric_zscore(data, "dst_host_srv_serror_rate")
    encode_numeric_zscore(data, "dst_host_rerror_rate")
    encode_numeric_zscore(data, "dst_host_srv_rerror_rate")

    return data.values


if __name__ == "__main__":
    read_data("data/extractor.txt")
