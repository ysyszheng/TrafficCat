import streamlit as st
import streamlit_echarts as st_echarts
import json
from datetime import datetime
from dateutil import parser
import pandas as pd

traffic_data = json.load(open("./data/output.json"))

for i in range(len(traffic_data)):
    traffic_data[i]['_parser'] = {}
    traffic_data[i]['_parser']['time'] = \
        parser.parse(traffic_data[i]['_source']['layers']['frame']['frame.time'])
    traffic_data[i]['_parser']['proto'] = traffic_data[i]['_source']['layers']['frame']['frame.protocols'].split(':')


counts = {}
for data in traffic_data:
    timestamp = data['_parser']['time']
    timestamp = timestamp.replace(microsecond=0)  # 忽略毫秒和微秒部分
    counts[timestamp] = counts.get(timestamp, 0) + 1

# 转换为时间序列和数量列表
timestamps = list(counts.keys())
timestamps.sort()  # 按时间排序
timestamp_strings = [timestamp.strftime("%Y-%m-%d %H:%M:%S") for timestamp in timestamps]
values = [counts[timestamp] for timestamp in timestamps]
values_df = pd.DataFrame(values, columns=['counts'], index=timestamp_strings)

# 在Streamlit网页中显示折线图
st.line_chart(values_df, use_container_width=True)

# 统计协议数量
protocol_counts = {}
for data in traffic_data:
    protocols = data['_parser']['proto']
    for protocol in protocols:
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

# 将协议数量转换为列表形式
protocol_labels = list(protocol_counts.keys())
protocol_values = list(protocol_counts.values())
protocol_df = pd.DataFrame(protocol_values, columns=['counts'], index=protocol_labels)

# 在Streamlit网页中显示柱状图
st.bar_chart(protocol_df, use_container_width=True)

