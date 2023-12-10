import datetime
import hashlib
import json
import requests
from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
users = {}
node_ips = ["127.0.0.1", "127.0.0.1", "127.0.0.1"]  # Replace with actual IP addresses
node_ports = [5000, 5001, 5002]  # Replace with actual port numbers


class User:
    def __init__(self):
        self.private_key, self.public_key = self.generate_key_pair()
        self.blockchain = Blockchain()
        self.known_nodes = []

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def add_known_node(self, node_id, ip_address, port):
        self.known_nodes.append((node_id, ip_address, port))

    def get_known_nodes(self):
        return list(self.known_nodes)


class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = {}
        self.generate_genesis_block()

    def generate_genesis_block(self):
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.current_transactions,
        }

        self.current_transactions = {}
        self.chain.append(block)
        return block

    def create_transaction(self, sender, recipient, amount, public_key):
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if serialized_public_key not in self.current_transactions:
            self.current_transactions[serialized_public_key] = []

        self.current_transactions[serialized_public_key].append(
            {
                'sender': sender,
                'recipient': recipient,
                'amount': amount,
            }
        )

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof ** 2 - previous_proof ** 2).encode()
            ).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    def hash(self, block):
        def convert_keys_to_str(obj):
            if isinstance(obj, bytes):
                return obj.decode('utf-8')
            elif isinstance(obj, dict):
                return {
                    convert_keys_to_str(k): convert_keys_to_str(v)
                    for k, v in obj.items()
                }
            elif isinstance(obj, list):
                return [convert_keys_to_str(elem) for elem in obj]
            else:
                return obj

        encoded_block = json.dumps(convert_keys_to_str(block), sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False

            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof ** 2 - previous_proof ** 2).encode()
            ).hexdigest()

            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1

        return True


class Node:
    def __init__(self, node_id, ip_address, port):
        self.node_id = node_id
        self.user = User()
        self.known_nodes = []
        self.ip_address = ip_address
        self.port = port

        # Register this node with existing nodes
        self.register_with_known_nodes()

        # Run Flask server
        self.app = Flask(__name__)
        self.register_endpoints()

    def register_with_known_nodes(self):
        for existing_node_id, existing_node_ip, existing_node_port in zip(users, node_ips, node_ports):
            if (isinstance(users[existing_node_id], Node) and existing_node_id != self.node_id):
                users[existing_node_id].add_known_node(
                    self.node_id, self.ip_address, self.port
                )
            self.known_nodes.append((existing_node_ip, existing_node_port))

    def register_endpoints(self):
        @self.app.route('/nodes/register', methods=['POST'])
        def register_node():
            data = request.get_json()
            node_id = data.get('node_id')
            if node_id:
                new_node = Node(node_id, None, None)
                users[node_id] = new_node.user

                # Update known nodes of the new node
                for existing_node_id, existing_node in users.items():
                    if (isinstance(existing_node, Node) and existing_node_id != node_id):
                        existing_node.add_known_node(node_id, new_node.ip_address, new_node.port)

                return jsonify({
                    'message': f'Node {node_id} registered successfully',
                    'known_nodes': new_node.get_known_nodes(),
                }), 201
            else:
                return jsonify({'message': 'Node registration failed. Provide a valid node_id.'}), 400

        @self.app.route('/mine_block', methods=['POST'])
        def mine_block():
            data = request.get_json()
            user_id = data.get('user_id')
            user = users.get(user_id)

            if not user:
                return jsonify({'message': 'User not found'}), 404

            previous_block = user.blockchain.last_block
            previous_proof = previous_block['proof']
            proof = user.blockchain.proof_of_work(previous_proof)
            previous_hash = user.blockchain.hash(previous_block)
            new_block = user.blockchain.create_block(proof, previous_hash)

            # Broadcast the new block to all known nodes
            broadcast_block(user_id, new_block)

            response = {
                'message': 'A block is MINED',
                'index': user.blockchain.last_block['index'],
                'timestamp': user.blockchain.last_block['timestamp'],
                'proof': user.blockchain.last_block['proof'],
                'previous_hash': user.blockchain.last_block['previous_hash'],
                'transactions': str(user.blockchain.last_block['transactions']),
            }

            return jsonify(response), 200

        @self.app.route('/receive_block', methods=['POST'])
        def receive_block():
            data = request.get_json()
            received_block = data.get('block')

            # Process the received block, validate it, and add it to the blockchain
            # (This part depends on your blockchain implementation)

            response = {'message': 'Block received successfully'}
            return jsonify(response), 200

    def run_server(self):
        self.app.run(host=self.ip_address, port=self.port)


def broadcast_block(node_id, block):
    user = users.get(node_id)
    if user:
        for known_node_ip, known_node_port in user.known_nodes:
            if (known_node_ip, known_node_port) != (user.ip_address, user.port):
                url = f'http://{known_node_ip}:{known_node_port}/receive_block'
                data = {'block': block}
                requests.post(url, json=data)


# Create nodes with different IP addresses and ports
node1 = Node("efe123", node_ips[0], node_ports[0])
node2 = Node("onur123", node_ips[1], node_ports[1])
node3 = Node("adnan123", node_ips[2], node_ports[2])

# Add known nodes to each node
node1.run_server()
node2.run_server()
node3.run_server()