#!/usr/local/bin/python
import os
import argparse
import pandas as pd
from pyvis.network import Network
import networkx as nx

parser = argparse.ArgumentParser(description='Palo Alto Firewall Security Policy Visualizer')
parser.add_argument("-sz", "--src_zone", help="Filter Visualization by Source Zone", dest='arg_src_zone', action='store', nargs='+')
parser.add_argument("-dz", "--dst_zone", help="Filter Visualization by Destination Zone", dest='arg_dst_zone', action='store', nargs='+')
parser.add_argument("-sip", "--src_ip", help="Filter Visualization by Source IP", dest='arg_src_ip', action='store', nargs='+')
parser.add_argument("-dip", "--dst_ip", help="Filter Visualization by Destination IP", dest='arg_dst_ip', action='store', nargs='+')
parser.add_argument("-t", "--tags", help="Filter Visualization by Tag", dest='arg_tags', action='store', nargs='+')
parser.add_argument("-g", "--group", help="Filter Visualization by Group", dest='arg_group', action='store', nargs='+')
parser.add_argument("-n", "--policy_name", help="Filter Visualization by Security Policy Name", dest='arg_policy_name', action='store', nargs='+')
parser.add_argument("-f", "--file", help="Specify a file not in the current working directory", dest='arg_file', action='store')
args = parser.parse_args()

cwd = os.getcwd()

def function_csv_to_df():
    global df_firewall_policies_original
    if args.arg_file is None:
        for filename in os.listdir(cwd):
            if filename.endswith(".csv"):
                with open(filename) as csv_file_import_security_policies:
                    df_firewall_policies_original = pd.read_csv(csv_file_import_security_policies)

    elif args.arg_file is not None:
        with open(args.arg_file) as csv_file_import_security_policies:
            df_firewall_policies_original = pd.read_csv(csv_file_import_security_policies)
def function_transform_args_to_vars():
    global arg_src_zone_join
    global arg_dst_zone_join
    global arg_src_ip_join
    global arg_dst_ip_join
    global arg_tags_join
    global arg_group_join
    global arg_policy_name_join
    #Source Zone
    if args.arg_src_zone is None:
        arg_src_zone_join = '.'
    elif args.arg_src_zone is not None:
        arg_src_zone_join = '|'.join(args.arg_src_zone)
    #Destination Zone
    if args.arg_dst_zone is None:
        arg_dst_zone_join = '.'
    elif args.arg_dst_zone is not None:
        arg_dst_zone_join = '|'.join(args.arg_dst_zone)
    #src_ip
    if args.arg_src_ip is None:
        arg_src_ip_join = '.'
    elif args.arg_src_ip is not None:
        arg_src_ip_join = '|'.join(args.arg_src_ip)
    #dst_ip
    if args.arg_dst_ip is None:
        arg_dst_ip_join = '.'
    elif args.arg_dst_ip is not None:
        arg_dst_ip_join = '|'.join(args.arg_dst_ip)
    #Tags
    if args.arg_tags is None:
        arg_tags_join = '.'
    elif args.arg_tags is not None:
        arg_tags_join = '|'.join(args.arg_tags)
    #group
    if args.arg_group is None:
        arg_group_join = '.'
    elif args.arg_group is not None:
        arg_group_join = '|'.join(args.arg_group)
    #policy_name
    if args.arg_policy_name is None:
        arg_policy_name_join = '.'
    elif args.arg_policy_name is not None:
        arg_policy_name_join = '|'.join(args.arg_policy_name)

def function_transform_df_filter_by_args():
    global df_firewall_policies_filtered_by_args
    df_firewall_policies_filtered_by_args = df_firewall_policies_original.loc[ \
        df_firewall_policies_original["Source Zone"].str.contains(str(arg_src_zone_join), case=False, na=False, regex=True) & \
        df_firewall_policies_original["Destination Zone"].str.contains(str(arg_dst_zone_join), case=False, na=False, regex=True) & \
        df_firewall_policies_original["Source Address"].str.contains(str(arg_src_ip_join), case=False, na=False, regex=True) & \
        df_firewall_policies_original["Destination Address"].str.contains(str(arg_dst_ip_join), case=False, na=False, regex=True) & \
        df_firewall_policies_original["Tags"].str.contains(str(arg_tags_join), case=False, na=False, regex=True) & \
        df_firewall_policies_original["Group"].str.contains(str(arg_group_join), case=False, na=False, regex=True) & \
        df_firewall_policies_original["Name"].str.contains(str(arg_policy_name_join), case=False, na=False, regex=True)]

def function_df_transform_df_for_visualization():
    global df_pyvis_net_params
    df_firewall_policies_filtered_all_for_visual = df_firewall_policies_filtered_by_args
    df_firewall_policies_filtered_all_for_visual['Source Address'] = df_firewall_policies_filtered_all_for_visual['Source Address'].str.split(';')
    df_firewall_policies_filtered_all_for_visual = df_firewall_policies_filtered_all_for_visual.explode('Source Address').reset_index(drop=True)
    df_firewall_policies_filtered_all_for_visual['Destination Address'] = df_firewall_policies_filtered_all_for_visual['Destination Address'].str.split(';')
    df_firewall_policies_filtered_all_for_visual = df_firewall_policies_filtered_all_for_visual.explode('Destination Address').reset_index(drop=True)
    df_firewall_policies_filtered_all_for_visual['Weight'] = '1'
    df_pyvis_net_params = df_firewall_policies_filtered_all_for_visual[['Source Address', 'Destination Address', 'Weight']]

def function_report_security_policy_visualization():
    firewall_net = Network(height='1080px', width='100%', bgcolor='#222222', font_color='white', select_menu=True, filter_menu=True)
    firewall_net.barnes_hut()

    sources = df_pyvis_net_params['Source Address']
    targets = df_pyvis_net_params['Destination Address']
    weights = df_pyvis_net_params['Weight']

    edge_data = zip(sources, targets, weights)

    for e in edge_data:
        src = e[0]
        dst = e[1]
        w = e[2]

        firewall_net.add_node(src, src, title=src)
        firewall_net.add_node(dst, dst, title=dst)
        firewall_net.add_edge(src, dst, value=w)

    neighbor_map = firewall_net.get_adj_list()

    # add neighbor data to node hover data
    for node in firewall_net.nodes:
        node['title'] += ' Neighbors:<br>' + '<br>'.join(neighbor_map[node['id']])
        node['value'] = len(neighbor_map[node['id']])

    firewall_net.toggle_physics(True)
    firewall_net.show_buttons(filter_=['physics'])
    firewall_net.show('security_policy_visualization.html')

function_csv_to_df()
function_transform_args_to_vars()
function_transform_df_filter_by_args()
function_df_transform_df_for_visualization()
function_report_security_policy_visualization()
