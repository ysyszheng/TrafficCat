import streamlit as st
from streamlit_echarts import st_echarts, st_pyecharts
import json
from datetime import datetime
from dateutil import parser
import pandas as pd
from pyecharts import options as opts
from pyecharts.charts import Graph, Pie

st.title("Traffic Analysis Dash Board")

# ----------------- upload file ----------------
traffic_data = None
with st.sidebar:
    uploaded_file = st.file_uploader("Choose pcap json file")
    if uploaded_file is not None:
        traffic_data = json.load(uploaded_file)

if traffic_data is not None:
    # ----------------- preprocessing -----------------
    for i in range(len(traffic_data)):
        traffic_data[i]['_parser'] = {}
        traffic_data[i]['_parser']['time'] = \
            parser.parse(traffic_data[i]['_source']['layers']['frame']['frame.time'])
        traffic_data[i]['_parser']['proto'] = traffic_data[i]['_source']['layers']['frame']['frame.protocols'].split(':')
        traffic_data[i]['_parser']['size'] = int(traffic_data[i]['_source']['layers']['frame']['frame.len'])
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

    # ----------------- time series -----------------
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

    # ----------------- protocol counts -----------------
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

    # ----------------- source ip link dst ip -----------------
    nodes = set()
    edges = []

    # 构建节点和边
    node_index = {}
    index = 0

    for data in traffic_data:
        src_ip = data['_parser'].get('src_ip')
        dst_ip = data['_parser'].get('dst_ip')
        
        if src_ip and dst_ip:
            if src_ip not in node_index:
                node_index[src_ip] = index
                index += 1
            if dst_ip not in node_index:
                node_index[dst_ip] = index
                index += 1
            
            nodes.add(src_ip)
            nodes.add(dst_ip)
            
            edges.append((node_index[src_ip], node_index[dst_ip]))

    # 转换为列表形式
    nodes = list(nodes)

    # 创建图表
    graph = (
        Graph()
        .add("", nodes, edges, layout="circular", linestyle_opts=opts.LineStyleOpts(curve=0.2))
        .set_global_opts(
            tooltip_opts=opts.TooltipOpts(trigger="item", trigger_on="mousemove"),
            legend_opts=opts.LegendOpts(is_show=False),
        )
        .set_series_opts(
            label_opts=opts.LabelOpts(
                position="right",
                formatter="{b}"
            )
        )
    )

    # ----------------- size -----------------
    # 统计包大小区间内的包数量
    size_counts = {
        "0-49": 0,
        "50-99": 0,
        "100-199": 0,
        "200-299": 0,
        "300-399": 0,
        "400-499": 0,
        "500-999": 0,
        "1000+": 0
    }

    for data in traffic_data:
        packet_size = data['_parser']['size']
        if packet_size < 50:
            size_counts["0-49"] += 1
        elif packet_size < 100:
            size_counts["50-99"] += 1
        elif packet_size < 200:
            size_counts["100-199"] += 1
        elif packet_size < 300:
            size_counts["200-299"] += 1
        elif packet_size < 400:
            size_counts["300-399"] += 1
        elif packet_size < 500:
            size_counts["400-499"] += 1
        elif packet_size < 1000:
            size_counts["500-999"] += 1
        else:
            size_counts["1000+"] += 1

    # 将包大小区间和数量转换为列表形式
    size_labels = list(size_counts.keys())
    size_values = list(size_counts.values())

    pie_size = (
        Pie()
        .add(
            "",
            [list(z) for z in zip(size_labels, size_values)],
        )
        .set_global_opts(
            legend_opts=opts.LegendOpts(is_show=False),
        )
        .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))
    )

    # ----------------- port access counts -----------------
    # 统计端口被访问的次数
    port_counts = {}

    for data in traffic_data:
        src_port = data['_parser'].get('src_port')
        dst_port = data['_parser'].get('dst_port')
        if src_port:
            port_counts[src_port] = port_counts.get(src_port, 0) + 1
        if dst_port:
            port_counts[dst_port] = port_counts.get(dst_port, 0) + 1

    # 将端口和访问次数转换为列表形式
    port_labels = list(port_counts.keys())
    port_values = list(port_counts.values())

    # 创建饼状图
    pie_port = (
        Pie()
        .add(
            "",
            [list(z) for z in zip(port_labels, port_values)],
        )
        .set_global_opts(
            legend_opts=opts.LegendOpts(is_show=False),
        )
        .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))
    )

    # ----------------- display traffic data as table -----------------
    df = pd.DataFrame([data['_parser'] for data in traffic_data])

    # ----------------- ui -----------------
    st.markdown("## Time Series")
    st.line_chart(values_df, use_container_width=True)
    st.write('## Traffic Data')
    st.dataframe(df)
    st.markdown("## Protocol Counts")
    st.bar_chart(protocol_df, use_container_width=True)
    st.write('## Traffic Graph')
    st_pyecharts(graph)
    col1, col2 = st.columns([1, 1])
    with col1:
        st.write('## Packet Size')
        st_pyecharts(pie_size)
    with col2:
        st.write('## Port Access')
        st_pyecharts(pie_port)
