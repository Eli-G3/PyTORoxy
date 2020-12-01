import stem.descriptor.remote
import public_constants


def clear_cache(filename: str):
    """
    Delete the current server descriptors that are in a given filename
    :param filename: filename of either guard, middle, or exit node
    :return:None
    """
    with open(filename, 'w') as f:
        f.truncate(0)


def get_bw_of_relays(node_type: str):
    """
    Gets the bandwidth of all nodes in the current consensus
    :param nodeType: The type of node to get (Exit, Middle, or Guard)
    :return: A dictionary of server descriptors with their bandwidth as keys
    """
    bw_of_relays = {}
    try:
        if node_type == "EXIT":
            # For all the Nodes is the consensus
            for desc in stem.descriptor.remote.get_server_descriptors().run():
                # If ther node has an exit policy (meaning it can be an exit node)
                if desc.exit_policy.is_exiting_allowed():
                    # Add the node to the bandwidth dictionary
                    bw_of_relays.setdefault(desc.observed_bandwidth, desc)
        else:
            # If guard or middle, get all the nodes and add them to the dictionary
            print("[*] Trying to get server descriptors")
            for desc in stem.descriptor.remote.get_server_descriptors().run():
                bw_of_relays.setdefault(desc.observed_bandwidth, desc)
            print("[*] Completed")

    except Exception as exc:
        print("[*] Unable to retrieve the server descriptors: %s" % exc)

    return bw_of_relays


def find_guards(bw_of_relays: dict):
    """
    Shortens a dict of bandwidth, server descriptors to only the nodes that are considered guard nodes.
    The Server Authority nodes are the ones who choose if a node can be a guard.
    :param bw_of_relays: The dictionary of bandwidth(key), server descriptors(value)
    :return:None
    """
    # Sort the dict keys by bandwidth from biggest to smallest
    sorted_keys = sorted(bw_of_relays.keys(), reverse=True)[:20]
    count = 0
    try:
        print("[*] Trying to get Consensus...")
        consensus = stem.descriptor.remote.get_consensus()
        print("[*] Completed")
    except Exception as exc:
        print("[*] Unable to retrieve the consensus: %s" % exc)
        return None
    for desc in consensus:
        for key in sorted_keys:
            # Cross reference the Nodes from the consensus with the nodes from the server descriptors file
            if desc.address == bw_of_relays[key].address:
                # If a given node is a Guard in the consensus (in the flags field)
                if 'Guard' in desc.flags:
                    print("[*] %s is a guard node" % desc.address)
                    try:
                        # Write the nodes server descriptor in GuardNodes.txt
                        with open('Authority_Directories\\GuardNodes.txt', 'a') as f:
                            f.write(str(bw_of_relays[key]))
                            f.write("\n\n")
                            count += 1
                    except Exception as exp:
                        print("[*] Error Writing to file:{}".format(exp))
        # Add DESCRIPTORS_IN_FILE amount of nodes to the file than stop
        if count >= public_constants.DESCRIPTORS_IN_FILE:
            break


def get_node_desc(node_type: str):
    """
    Get the server descriptors for a given node type, and write them in the corresponding file
    :param node_type: the type of node (Guard, Exit, Middle)
    :return: None
    """
    bw_of_relays = get_bw_of_relays(node_type)
    count = 0

    if node_type == "GUARD":
        print("[*] Finding Guards")
        find_guards(bw_of_relays)
    else:
        # Sort bandwidth from greatest to smallest
        for key in sorted(bw_of_relays.keys(), reverse=True):
            try:
                # Write the server descriptors in the corresponding file based on node type
                if node_type == "EXIT":
                    with open('Authority_Directories\\ExitNodes.txt', 'a') as f:
                        f.write(str(bw_of_relays[key]))
                        f.write("\n\n\n\n")
                        count += 1
                else:
                    with open('Authority_Directories\\MiddleNodes.txt', 'a') as f:
                        f.write(str(bw_of_relays[key]))
                        f.write("\n\n\n\n")
                        count += 1
            except Exception as exp:
                print("[*] Error Writing to file:{}".format(exp))
            if count >= public_constants.DESCRIPTORS_IN_FILE:
                break

