import streamlit as st
import streamlit_echarts as st_echarts
import json
from datetime import datetime
from dateutil import parser
import matplotlib.pyplot as plt
import pandas as pd
import networkx as nx

traffic_data = json.load(open("./data/output.json"))

for i in range(len(traffic_data)):
    traffic_data[i]['_parser'] = {}
    traffic_data[i]['_parser']['time'] = \
        parser.parse(traffic_data[i]['_source']['layers']['frame']['frame.time'])
    traffic_data[i]['_parser']['proto'] = traffic_data[i]['_source']['layers']['frame']['frame.protocols'].split(':')
    if 'ip' in traffic_data[i]['_parser']['proto']:
        traffic_data[i]['_parser']['dst_ip'] = traffic_data[i]['_source']['layers']['ip']['ip.dst']
        traffic_data[i]['_parser']['src_ip'] = traffic_data[i]['_source']['layers']['ip']['ip.src']
    elif 'arp' in traffic_data[i]['_parser']['proto']:
        traffic_data[i]['_parser']['dst_ip'] = traffic_data[i]['_source']['layers']['arp']['arp.dst.proto_ipv4']
        traffic_data[i]['_parser']['src_ip'] = traffic_data[i]['_source']['layers']['arp']['arp.src.proto_ipv4']
    if 'tcp' in traffic_data[i]['_parser']['proto']:
        traffic_data[i]['_parser']['dst_port'] = traffic_data[i]['_source']['layers']['tcp']['tcp.dstport']
        traffic_data[i]['_parser']['src_port'] = traffic_data[i]['_source']['layers']['tcp']['tcp.srcport']
    elif 'udp' in traffic_data[i]['_parser']['proto']:
        traffic_data[i]['_parser']['dst_port'] = traffic_data[i]['_source']['layers']['udp']['udp.dstport']
        traffic_data[i]['_parser']['src_port'] = traffic_data[i]['_source']['layers']['udp']['udp.srcport']


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

# 创建带权重的网络图谱对象
G = nx.Graph()

# 计算每条边的权重
edge_weights = {}
for data in traffic_data:
    src_ip = data['_parser'].get('src_ip')
    dst_ip = data['_parser'].get('dst_ip')
    if src_ip and dst_ip:
        edge = (src_ip, dst_ip)
        edge_weights[edge] = edge_weights.get(edge, 0) + 1

# 添加带权重的边
for edge, weight in edge_weights.items():
    G.add_edge(edge[0], edge[1], weight=weight)

# 绘制网络图谱
plt.figure(figsize=(10, 6))
pos = nx.spring_layout(G, k=0.3)  # 设置布局
edge_widths = [G[u][v]['weight'] for u, v in G.edges()]

# 绘制节点
nx.draw_networkx_nodes(G, pos, node_size=100, node_color='skyblue')

# 绘制边
nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.3)

# 绘制节点标签
nx.draw_networkx_labels(G, pos, font_size=8)

plt.title('Traffic Network')
plt.axis('off')
plt.tight_layout()

# 在Streamlit网页中显示网络图谱
st.pyplot(plt)