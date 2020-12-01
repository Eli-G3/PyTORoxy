import re
from node import Node
import random
import public_constants

node_files = {'GUARD': 'C:\\Users\\eli\\PycharmProjects\\Tor_Client\\Authority_Directories\\GuardNodes.txt',
                  'MIDDLE': 'C:\\Users\\eli\\PycharmProjects\\Tor_Client\\Authority_Directories\\MiddleNodes.txt',
                  'EXIT': 'C:\\Users\\eli\\PycharmProjects\\Tor_Client\\Authority_Directories\\ExitNodes.txt'}

# NODE_POS = which relay to read from in the txt file, there are DESCRIPTORS_IN_FILE [0-DESCRIPTORS_IN_FILE-1]
def parse_node(node_type: str, NODE_POS: int = 0):
    """
    Parses the file of a server descriptor for the NODE_POS node
    In each file there are DESCRIPTORS_IN_FILE node descriptors
    :param node_type: The type of node (Guard, Middle or Exit)
    :param NODE_POS: The nth descriptor in the file
    :return: the created Node
    """
    with open(node_files[node_type], 'r') as f:
        desc = f.read()
        # Use Regular Expressions to find the host(ip address), port, onion key, and identity key of the node at NODE_POS
        host = re.findall(r'router .+ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \w', desc)[NODE_POS].split()[2]
        port = int(re.findall(r'router .+ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \d+', desc)[NODE_POS].split()[3])
        onion_key = '\n'.join(
            re.findall(r'onion-key\n-----BEGIN RSA PUBLIC KEY-----\n\S+\n\S+\n\S+=\n-----END RSA PUBLIC KEY-----',
                       desc)[NODE_POS].split('\n')[1:])
        identity_key = '\n'.join(
            re.findall(r'signing-key\n-----BEGIN RSA PUBLIC KEY-----\n\S+\n\S+\n\S+=\n-----END RSA PUBLIC KEY-----',
                       desc)[NODE_POS].split('\n')[1:])
        min_link_version = int(re.findall(r'Link=\S+', desc)[NODE_POS].strip('Link=')[0])
    # Create the node with its initial values and return it
    node = Node(host, port, node_type, onion_key, identity_key, min_link_version)
    return node


def has_overlaps(node_list: list):
    """
    Checks if we have the same node for two or more positions.
    i.e. if the guard and middle nodes are actually the same node
    :param node_list:
    :return:
    """
    return node_list[0].host == node_list[1].host \
           or node_list[0].host == node_list[2].host \
           or node_list[1].host == node_list[2].host


def get_circuit_nodes():
    """
    Parses a node of each type and joins them into a list of nodes to give to a circuit object
    :return: the list of nodes
    """
    # The starting positiosn in the file to read from
    # It can increment or decrement but it has to stay in the range of 0 to DESCRIPTORS_IN_FILE
    node_pos_exit = 1
    node_pos_middle = 1
    node_list = [parse_node('GUARD'), parse_node('MIDDLE'), parse_node('EXIT')]
    # While the node list has overlaps, change the middle or exit node
    while has_overlaps(node_list):
        # randomly choose the middle (1) or exit (2) node
        pos = random.randint(1, 2)
        # Parse a different node in the file
        if pos == 1:
            if 0 <= node_pos_middle <= public_constants.DESCRIPTORS_IN_FILE:
                node_list[pos] = parse_node('MIDDLE', node_pos_middle)
                if node_pos_middle == public_constants.DESCRIPTORS_IN_FILE:
                    node_pos_middle -= 1
                else:
                    node_pos_middle += 1
        else:
            # Parse a different node in the file
            if 0 <= node_pos_exit <= public_constants.DESCRIPTORS_IN_FILE:
                node_list[pos] = parse_node('EXIT', node_pos_exit)
                if node_pos_exit == public_constants.DESCRIPTORS_IN_FILE:
                    node_pos_exit -= 1
                else:
                    node_pos_middle += 1
    # Once no two nodes in the list are the same, return the list
    return node_list
