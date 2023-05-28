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
#with st.sidebar:
#    uploaded_file = st.file_uploader("Choose pcap json file")
#    if uploaded_file is not None:
#        traffic_data = json.load(uploaded_file)

traffic_data = json.load(open('data/traffic.json', 'r'))

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
        timestamp = timestamp.replace(microsecond=0)  # Ignore millisecond and microsecond parts
        counts[timestamp] = counts.get(timestamp, 0) + 1

    # Conversion to time series and volume lists
    timestamps = list(counts.keys())
    timestamps.sort()  # Sort by time
    timestamp_strings = [timestamp.strftime("%Y-%m-%d %H:%M:%S") for timestamp in timestamps]
    values = [counts[timestamp] for timestamp in timestamps]
    values_df = pd.DataFrame(values, columns=['counts'], index=timestamp_strings)

    # ----------------- protocol counts -----------------
    # Number of statistical agreements and their hierarchy
    protocol_counts = {}
    protocol_hierarchy = {}
    for data in traffic_data:
        protocols = data['_parser']['proto']
        for i, protocol in enumerate(protocols):
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            if i < len(protocols) - 1:
                if protocol not in protocol_hierarchy:
                    protocol_hierarchy[protocol] = []
                if protocols[i + 1] not in protocol_hierarchy[protocol]:
                    protocol_hierarchy[protocol].append(protocols[i + 1])

    # Converting the number of agreements into list form
    protocol_labels = list(protocol_counts.keys())
    protocol_values = list(protocol_counts.values())
    protocol_df = pd.DataFrame(protocol_values, columns=['counts'], index=protocol_labels)

    # Getting to the protocol level
    def get_protocol_hierarchy(protocol):
        hierarchy = []
        while protocol:
            if protocol not in ['eth', 'ethertype']:
                hierarchy.append(protocol)
            for parent, children in protocol_hierarchy.items():
                if protocol in children:
                    protocol = parent
                    break
            else:
                break
        hierarchy.reverse()
        return hierarchy
    
    # Defining protocol colours
    protocol_colors = {
        'ip': '#6495ED',
        'tcp': '#7FFF00',
        'udp': '#FF4500',
        'icmp': '#FFD700',
        'http': '#ADFF2F',
        'https': '#FF69B4',
        'arp': '#D2691E',
        'rarp': '#1E90FF',
        'ipv6': '#DC143C',
        'igmp': '#20B2AA',
        'ippc': '#2F4F4F',
        'sctp': '#FFDAB9',
        'ftp': '#B0C4DE',
        'ssh': '#ADD8E6',
        'telnet': '#87CEFA',
        'smtp': '#87CEEB',
        'dns': '#6A5ACD',
        'dhcp': '#708090',
        'smb': '#4682B4',
        'pop3': '#4169E1',
        'imap': '#40E0D0',
        'snmp': '#EE82EE',
        'ldap': '#D8BFD8',
        'tftp': '#DDA0DD',
        'rip': '#9932CC',
        'tls': '#9400D3',      
    }
    
    # Get the protocol tree
    def get_protocol_tree(protocol_counts):
        protocol_tree = {"name": "root", "children": []}
    
        # Add to the protocol tree
        def add_to_tree(protocol, count):
            current_level = protocol_tree
            protocol_parts = get_protocol_hierarchy(protocol)
            
            for part in protocol_parts:
                if part not in [child['name'] for child in current_level['children']]:
                    new_part = {"name": part, "value": count, "children": [], "itemStyle": {"color": protocol_colors.get(part, '#808080')}}
                    current_level['children'].append(new_part)
                    current_level = new_part
                else:
                    for child in current_level['children']:
                        if child['name'] == part:
                            child['value'] += count
                            current_level = child

        for protocol, count in protocol_counts.items():
            add_to_tree(protocol, count)
        return protocol_tree

    protocol_tree = get_protocol_tree(protocol_counts)
    
    # options for protocol tree
    option = {
        "series": {
            "type": "sunburst",
            "highlightPolicy": "ancestor",
            "data": [child for child in protocol_tree['children'] if child['name'] not in ['eth', 'ethertype']],
            "radius": [0, "95%"],
            "sort": None,
            "label": {
                "fontSize": 12,
                "overflow": "ellipsis"
            },
            "levels": [
                {},
                {
                    "r0": "15%",
                    "r": "35%",
                    "itemStyle": {"borderWidth": 2},
                    "label": {"rotate": "tangential"},
                },
                {
                    "r0": "35%",
                    "r": "70%",
                    "label": {"align": "right"},
                },
                {
                    "r0": "70%",
                    "r": "72%",
                    "label": {"position": "outside", "padding": 3, "silent": False},
                    "itemStyle": {"borderWidth": 3}
                }
            ],
        },
    }

    # ----------------- source ip link dst ip -----------------
    nodes = []
    edges = []

    # Constructing nodes and edges
    node_index = {}
    index = 0

    for data in traffic_data:
        src_ip = data['_parser'].get('src_ip')
        dst_ip = data['_parser'].get('dst_ip')

        if src_ip and dst_ip:
            if src_ip not in node_index:
                node_index[src_ip] = index
                nodes.append({"name": src_ip, "symbolSize": 10})
                index += 1
            if dst_ip not in node_index:
                node_index[dst_ip] = index
                nodes.append({"name": dst_ip, "symbolSize": 10})
                index += 1

            edges.append({"source": src_ip, "target": dst_ip})

    # Creating charts
    graph = (
        Graph(init_opts=opts.InitOpts(width="1000px", height="600px"))
        .add("", nodes, edges, repulsion=8000, layout='circular', is_roam=True)
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
    # Count the number of packets in the packet size interval
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

    # Converting package size intervals and quantities to list form
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
    # Count the number of times the port has been accessed
    port_counts = {}

    for data in traffic_data:
        src_port = data['_parser'].get('src_port')
        dst_port = data['_parser'].get('dst_port')
        if src_port:
            port_counts[src_port] = port_counts.get(src_port, 0) + 1
        if dst_port:
            port_counts[dst_port] = port_counts.get(dst_port, 0) + 1

    # Converting ports and accesses into list form
    port_labels = list(port_counts.keys())
    port_values = list(port_counts.values())

    # Create a pie chart
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

    # ----------------- src ip addr counts -----------------
    # Count the number of times the source ip address appears
    src_ip_counts = {}
    for data in traffic_data:
        src_ip = data['_parser'].get('src_ip')
        if src_ip:
            src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1

    # Converting ip addresses and occurrences into list form
    src_ip_labels = list(src_ip_counts.keys())
    src_ip_values = list(src_ip_counts.values())
    
    # Create a pie chart
    pie_src_ip = (
        Pie()
        .add(
            "",
            [list(z) for z in zip(src_ip_labels, src_ip_values)],
        )
        .set_global_opts(
            legend_opts=opts.LegendOpts(is_show=False),
        )
        .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))
    )

    # ----------------- dst ip addr counts -----------------
    # Count the number of occurrences of the destination ip address
    dst_ip_counts = {}
    for data in traffic_data:
        dst_ip = data['_parser'].get('dst_ip')
        if dst_ip:
            dst_ip_counts[dst_ip] = dst_ip_counts.get(dst_ip, 0) + 1

    # Converting ip addresses and occurrences into list form
    dst_ip_labels = list(dst_ip_counts.keys())
    dst_ip_values = list(dst_ip_counts.values())

    # Create a pie chart
    pie_dst_ip = (
        Pie()
        .add(
            "",
            [list(z) for z in zip(dst_ip_labels, dst_ip_values)],
        )
        .set_global_opts(
            legend_opts=opts.LegendOpts(is_show=False),
        )
        .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))
    )

    # ----------------- display traffic data as table -----------------
    df = pd.DataFrame([data['_parser'] for data in traffic_data])

    # ----------------- label count -----------------
    # Reading text files
    file_path = "./data/label.txt"
    with open(file_path, "r") as file:
        lines = file.readlines()

    # Count the number of each label
    label_counts = pd.Series(lines).value_counts()
    label_percent = label_counts / label_counts.sum()

    # Creating data boxes
    df_label = pd.DataFrame({"Label": label_counts.index, "Percent": label_percent.values})

    # Drawing pie charts
    pie_chart = (
        Pie()
        .add("", df_label.values.tolist())
        .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))
    )

    # ---------------- ui ----------------
    st.markdown("## Time Series")
    st.line_chart(values_df, use_container_width=True)

    st.write('## Traffic Data')
    st.dataframe(df)
    idx = st.text_input(f'Input traffic index in above table, from 0 to {len(df)-1}')
    if idx:
        if idx.isdigit():
            idx = int(idx)
            if idx >= 0 and idx < len(df):
                st.write(traffic_data[idx]['_source'])
            else:
                st.error('Invalid index')
        else:
            st.error('Invalid index')
    
    st.markdown("## Protocol Counts")
    st.bar_chart(protocol_df, use_container_width=True)
    
    st.markdown("## Protocol Sunburst")
    st_echarts(option, height="600px")
    
    st.write('## Traffic Graph')
    st_pyecharts(graph, height="600px")
    
    col1, col2 = st.columns([1, 1])
    with col1:
        st.write('## Source IP Address')
        st_pyecharts(pie_src_ip)
    with col2:
        st.write('## Destination IP Address')
        st_pyecharts(pie_dst_ip)

    col1, col2 = st.columns([1, 1])
    with col1:
        st.write('## Packet Size')
        st_pyecharts(pie_size)
    with col2:
        st.write('## Port Access')
        st_pyecharts(pie_port)
    

    st.write('## Traffic Label')
    st_pyecharts(pie_chart, height="600px")
