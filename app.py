import datetime
import hashlib
import json
from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, padding



class User:
    def __init__(self, user_id):
        self.private_key, self.public_key = self.generate_key_pair()
        self.blockchain = Blockchain()
        self.known_users = []
        self.user_id = user_id
	
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def add_known_user(self, user_id):
        self.known_users.append(user_id)
    
    def get_known_users(self):
        return list(self.known_users)
	
class Blockchain:
	def __init__(self):
		self.chain = []
		self.current_transactions = {}
		self.generate_genesis_block()
		
	def get_all_transactions(self):
		pass
	
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
	

app = Flask(__name__)
users = {}

# efe = User(user_id="efe123")
# efe_id = "efe123"
# users[efe_id] = efe

# onur = User(user_id="onur123")
# onur_id = "onur123"
# users[onur_id] = onur

@app.route('/users/register', methods=['POST'])
def register_user():
    data = request.get_json()
    user_id = data.get('user_id')
    if user_id:
        new_user = User(user_id)
        users[user_id] = new_user

        for existing_user_id, existing_user in users.items():
            if isinstance(existing_user, User) and existing_user_id != user_id:
                existing_user.add_known_user(user_id)
        
        return jsonify({
            'message': f'User {user_id} registered successfully',
            'known_users': new_user.get_known_users()
        }), 201
    else:
        return jsonify({'message': 'User registration failed. Provide a valid user_id.'}), 400
	

@app.route('/add_transaction/<user_id>', methods=['POST'])
def add_transaction(user_id):
	data = request.get_json()

	required_fields = ['sender', 'recipient', 'amount']
	if not all(field in data for field in required_fields):
		return 'Missing fields', 400

	user = users.get(user_id)
	sender = users.get(data['recipient'])
	if not user or not sender:
		return jsonify({'message': 'User not found'}), 404
	if data['sender'] == user_id:
		user.blockchain.create_transaction(data['sender'], data['recipient'], data['amount'], user.public_key)
		response = {'message': 'Transaction added to current transactions'}
		print(user.blockchain.current_transactions)
		return jsonify(response), 201
	else:
		response = {'message': 'Sender is not equal to user_id'}
		return jsonify(response), 400
	
@app.route('/broadcast_transaction/<user_id>', methods=['POST'])
def broadcast_transaction(user_id):
    data = request.get_json()

    required_fields = ['sender', 'recipient', 'amount']
    if not all(field in data for field in required_fields):
        return 'Missing fields', 400

    user = users.get(user_id)
    sender = users.get(data['recipient'])
	
    if not user or not sender:
        return jsonify({'message': 'User not found'}), 404
    if data['sender'] == user_id:
        user.blockchain.create_transaction(data['sender'], data['recipient'], data['amount'], user.public_key)
    else:
        return
    
    for user_id in user.get_known_users():
        if sender != user_id:  # Skip broadcasting to the user who initiated the transaction
            user = users.get(user_id)
            user.blockchain.create_transaction(data['sender'], data['recipient'], data['amount'], sender.public_key)
            print(user.blockchain.current_transactions)

    # Response to the client
    response = {'message': 'Transaction added and broadcasted successfully'}
    return jsonify(response), 201

@app.route('/get_current_transaction/<user_id>', methods=['GET'])
def get_current_transaction(user_id):
	user = users.get(user_id)
	print(user.blockchain.current_transactions)
	response = {'message': 'current list'}
	return jsonify(response), 201

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

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)