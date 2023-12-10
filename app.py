import datetime
import hashlib
import json
from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, padding


class User:
	def __init__(self):
		self.private_key, self.public_key = self.generate_key_pair()
		self.blockchain = Blockchain()
		self.known_nodes = []
	def generate_key_pair(self):
		private_key = rsa.generate_private_key(
				public_exponent=65537,
				key_size=2048,
				backend=default_backend()
		)
		public_key = private_key.public_key()
		return private_key, public_key
	def add_known_node(self, node_id):
		self.known_nodes.append(node_id)
	
	def get_known_nodes(self):
		return list(self.known_nodes)

class Blockchain:

	def __init__(self):
		self.chain = []
		self.current_transactions = {}
		self.generate_genesis_block()
	def get_all_transactions(self):
		all_transactions = []
		for block in self.chain:
			transactions = block['transactions']
			all_transactions.extend(transactions)
		return all_transactions
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
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		if serialized_public_key not in self.current_transactions:
			self.current_transactions[serialized_public_key] = []

		self.current_transactions[serialized_public_key].append({
			'sender': sender,
			'recipient': recipient,
			'amount': amount,
		})

	@property
	def last_block(self):
		return self.chain[-1]

	def proof_of_work(self, previous_proof):
		new_proof = 1
		check_proof = False

		while check_proof is False:
			hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
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
				return {convert_keys_to_str(k): convert_keys_to_str(v) for k, v in obj.items()}
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
			hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()

			if hash_operation[:5] != '00000':
					return False
			previous_block = block
			block_index += 1

		return True

class Node:
	def __init__(self, node_id):
		self.node_id = node_id
		self.user = User()
		self.known_nodes = []
	
	def add_known_node(self, node_id):
		self.known_nodes.append(node_id)
	
	def get_known_nodes(self):
		return list(self.known_nodes)


	
app = Flask(__name__)
users = {}

efe = User()
efe_id = "efe123"
users[efe_id] = efe

onur = User()
onur_id = "onur123"
users[onur_id] = onur

adnan = User()
adnan_id = "adnan123"
users[adnan_id] = adnan

# Example Node registration endpoint
@app.route('/nodes/register', methods=['POST'])
def register_node():
    data = request.get_json()
    node_id = data.get('node_id')
    if node_id:
        new_node = Node(node_id)
        users[node_id] = new_node.user
		# Update known nodes of the new node
        for existing_node_id, existing_node in users.items():
            if isinstance(existing_node, Node) and existing_node_id != node_id:
                existing_node.add_known_node(node_id)
        print(existing_node)
        return jsonify({
            'message': f'Node {node_id} registered successfully',
            'known_nodes': new_node.get_known_nodes()
        }), 201
    else:
        return jsonify({'message': 'Node registration failed. Provide a valid node_id.'}), 400
	
@app.route('/mine_block/<user_id>', methods=['GET'])
def mine_block(user_id):
	user = users.get(user_id)

	if not user:
		return jsonify({'message': 'User not found'}), 404

	previous_block = user.blockchain.last_block
	previous_proof = previous_block['proof']
	proof = user.blockchain.proof_of_work(previous_proof)
	previous_hash = user.blockchain.hash(previous_block)
	user.blockchain.create_block(proof, previous_hash)

	response = {
    'message': 'A block is MINED',
    'index': user.blockchain.last_block['index'],
    'timestamp': user.blockchain.last_block['timestamp'],
    'proof': user.blockchain.last_block['proof'],
    'previous_hash': user.blockchain.last_block['previous_hash'],
    'transactions': str(user.blockchain.last_block['transactions'])  # Convert bytes to string
	}

	return jsonify(response), 200


@app.route('/get_chain/<user_id>', methods=['GET'])
def display_chain(user_id):
    user = users.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    def convert_keys_to_str(obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        elif isinstance(obj, dict):
            return {convert_keys_to_str(k): convert_keys_to_str(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_keys_to_str(elem) for elem in obj]
        else:
            return obj

    response = {
        'chain': convert_keys_to_str(user.blockchain.chain),
        'length': len(user.blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/valid/<user_id>', methods=['GET'])
def valid(user_id):
	user = users.get(user_id)

	if not user:
		return jsonify({'message': 'User not found'}), 404

	valid = user.blockchain.chain_valid(user.blockchain.chain)

	if valid:
		response = {'message': 'The Blockchain is valid.'}
	else:
		response = {'message': 'The Blockchain is not valid.'}
	return jsonify(response), 200


@app.route('/add_transaction/<user_id>', methods=['POST'])
def add_transaction(user_id):
	data = request.get_json()

	required_fields = ['sender', 'recipient', 'amount']
	if not all(field in data for field in required_fields):
		return 'Missing fields', 400

	user = users.get(user_id)

	if not user:
		return jsonify({'message': 'User not found'}), 404

	user.blockchain.create_transaction(data['sender'], data['recipient'], data['amount'], user.public_key)
	response = {'message': 'Transaction added to current transactions'}
	return jsonify(response), 201
	#user = users.get(user_id)

	#if not user:
	#	return jsonify({'message': 'User not found'}), 404

	#user.blockchain.create_transaction(data['sender'], data['recipient'], data['amount'])

	#response = {'message': 'Transaction added to current transactions'}
	#return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def resolve_conflicts():
    for node_id, node in users.items():
        node_chain = node.blockchain.chain
        if not node.blockchain.chain_valid(node_chain):
            # Resolve conflicts by replacing the chain with the longest valid chain
            longest_chain = max([n.blockchain.chain for n in users.values()], key=len)
            node.blockchain.chain = longest_chain

    # Get the list of known nodes after resolving conflicts
    known_nodes_after_resolution = list(users.values())[0].get_known_nodes()

    response = {
        'message': 'Conflict resolution completed',
        'known_nodes': known_nodes_after_resolution
    }

    return jsonify(response), 200

all_transactions = {'transaction1': b'binary_data1', 'transaction2': b'binary_data2'}

@app.route('/get_all_transactions/<user_id>', methods=['GET'])
def get_all_transactions(user_id):
    # Convert bytes data to a serializable format (e.g., hexadecimal)
    serialized_transactions = {key: value.hex() for key, value in all_transactions.items()}
    return jsonify({'all_transactions': serialized_transactions}), 200