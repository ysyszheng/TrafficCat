import numpy as np
import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder


# normalize
def encode_numeric_zscore(df, name, mean=None, sd=None):
    if mean is None:
        mean = df[name].mean()

    if sd is None:
        sd = df[name].std()

    df[name] = (df[name] - mean) / sd


# label encoding
def encode_text_dummy(df, name, encoder=False):
    if encoder is False:
        encoder = LabelEncoder()
        encoder.fit(df[name])
        with open("kdd/inference/encoder/" + name + "_encoder.pkl", "wb") as f:
            pickle.dump(encoder, f)
    else:
        with open("kdd/inference/encoder/" + name + "_encoder.pkl", "rb") as f:
            encoder = pickle.load(f)
    df[name] = encoder.transform(df[name])


def read_data(path):
    data = pd.read_csv(path, header=None)
    data.columns = [
        "duration",  # Duration, in the range [0, 58329]
        "protocol_type",  # Protocol types, three: TCP, UDP, ICMP
        "service",  # The network service type of the target host, there are 70 types, such as 'http_443′, 'http_8001′, 'imap4′, etc.
        "flag",  # Connecting normal or wrong states, discrete types, 11 types in total, such as 'S0′, 'S1′, 'S2′, etc.
        "src_bytes",  # Number of bytes of data from the source host to the destination host in the range [0,1379963888]
        "dst_bytes",  # Number of bytes of data from the target host to the source host, in the range [0.1309937401]
        "land",  # 1 if the connection comes from/sends to the same host/port, 0 otherwise
        "wrong_fragment",  # Number of error segments, continuous type, in the range [0,3]
        "urgent",  # Number of expedited packages, continuous type, in the range [0,14]
        "count",  # Number of connections with the same target host as the current connection in the last two seconds, in the range [0,511]
        "srv_count",  # Number of connections with the same service as the current connection in the last two seconds, in the range [0,511]
        "serror_rate",  # Percentage of connections with the same destination host as the current connection that had a "SYN" error in the last two seconds, in the range [0.00,1.00]
        "srv_serror_rate",  # Percentage of connections with the same service as the current connection that had a "SYN" error in the last two seconds, in the range [0.00,1.00]
        "rerror_rate",  # Percentage of connections with the same target host as the current connection that had a "REJ" error in the last two seconds, in the range [0.00,1.00]
        "srv_rerror_rate",  # Percentage of connections with the same service as the current connection that had a "REJ" error in the last two seconds, in the range [0.00,1.00]
        "same_srv_rate",  # Percentage of connections with the same destination host as the current connection that have the same service as the current connection in the last two seconds, in the range [0.00,1.00]
        "diff_srv_rate",  # Percentage of connections with different services from the current connection in the last two seconds among connections with the same target host as the current connection, in the range [0.00,1.00]
        "srv_diff_host_rate",  # Percentage of connections with different target hosts from the current connection in the last two seconds among connections with the same service as the current connection, in the range [0.00,1.00]
        "dst_host_count",  # The number of connections in the first 100 connections that have the same target host as the current connection, in the range [0,255]
        "dst_host_srv_count",  # The number of connections in the first 100 connections that have the same target host with the same service as the current connection, in the range [0,255]
        "dst_host_same_srv_rate",  # The percentage of the first 100 connections that have the same services with the same target host as the current connection, in the range [0.00,1.00]
        "dst_host_diff_srv_rate",  # Percentage of the first 100 connections that have different services with the same target host as the current connection, in the range [0.00,1.00]
        "dst_host_same_src_port_rate",  # Percentage of the first 100 connections that have the same source port of the same target host as the current connection, in the range [0.00,1.00]
        "dst_host_srv_diff_host_rate",  # Percentage of the first 100 connections that have the same target host with the same service as the current connection that have a different source host than the current connection, in the range [0.00,1.00]
        "dst_host_serror_rate",  # Percentage of connections with SYN errors among the first 100 connections with the same destination host as the current connection, in the range [0.00,1.00]
        "dst_host_srv_serror_rate",  # Percentage of the first 100 connections with the same target host with the same service as the current connection that have SYN errors, in the range [0.00,1.00]
        "dst_host_rerror_rate",  # dst_host_rerror_rate. Percentage of the first 100 connections with the same destination host as the current connection that have REJ errors, in the range [0.00,1.00]
        "dst_host_srv_rerror_rate",  # Percentage of the first 100 connections that have the same target host with the same service as the current connection that have REJ errors, in the range [0.00,1.00]
    ]

    if "oth_i" in data["service"].values:
        # Matching rows exist, delete them
        matching_rows = data[data["service"] == "oth_i"]
        data = data.drop(matching_rows.index)


    # Each data item is processed accordingly
    encode_numeric_zscore(data, "duration")
    encode_text_dummy(data, "protocol_type", True)
    encode_text_dummy(data, "service", True)
    encode_text_dummy(data, "flag", True)
    encode_numeric_zscore(data, "src_bytes")
    encode_numeric_zscore(data, "dst_bytes")
    encode_text_dummy(data, "land", True)
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
    read_data("./input/input_data.txt")
