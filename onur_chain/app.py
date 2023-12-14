import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import requests
from flask import Flask, jsonify, request
from flask import render_template


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.users = {}
        self.new_block(previous_hash='1', proof=100)

    def get_user_list(self):
        return list(self.users.keys())
    def update_user_list(self, users):
        self.users = users
        
    def broadcast_user_list(self):
        for node in self.nodes:
            user_list = self.get_user_list()
            payload = {'users': user_list}
            requests.post(f'http://{node}/update_user_list', json=payload)
    
    def broadcast_nodes(self):
        for node in self.nodes:
            payload = {'nodes': list(self.nodes)}
            requests.post(f'http://{node}/nodes/register', json=payload)

    def register_user(self, username, password):
        if username not in self.users:
            user_id = str(uuid4())
            self.users[username] = {
                'id': user_id,
                'password': password,
                'balance': 100  # Initial balance is set to 0
            }
            self.broadcast_user_list()  # Broadcast the updated user list
            return user_id
        else:
            return None  # User already exists

    def get_user_balance(self, username):
        if username in self.users:
            user_balance = 0

            for block in self.chain:
                for transaction in block['transactions']:
                    if transaction['sender'] == username:
                        user_balance -= transaction['amount']
                    elif transaction['recipient'] == username:
                        user_balance += transaction['amount']
            return user_balance + self.users[username]['balance']
        else:
            return None  # User not found
        
    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):

        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            self.current_transactions = []
            return True

        return False

    def new_block(self, proof, previous_hash):


        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        

        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount,sender_password):
        sender_balance = self.get_user_balance(sender)

        if sender_balance is None:
            return 'Sender not found', 404

        try:
            amount = int(amount)
        except ValueError:
            return 'Invalid amount', 400

        if sender_password == self.users[sender]['password']:
            if sender_balance >= amount:
                self.current_transactions.append({
                    'sender': sender,
                    'recipient': recipient,
                    'amount': amount,
                })
                return self.last_block['index'] + 1
            else:
                return 'Insufficient balance', 400
        else:
            return 'Incorrect password', 401

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

def register_nodes_on_start(port):
    if port != 5000:  # Assuming DEFAULT_PORT is the port where Flask is running
        registration_url = f'http://127.0.0.1:5000/nodes/signin'
        payload = {'url': f'http://127.0.0.1:{port}'}
        
        try:
            requests.post(registration_url, json=payload)
            print(f"Node on port {port} registered successfully.")
        except requests.exceptions.ConnectionError:
            print(f"Failed to register node on port {port}. Make sure the main server is running.")
# ... (rest of your code)

from flask_cors import CORS

# Instantiate the Node
app = Flask(__name__, template_folder='templates')
CORS(app)  # Enable CORS for all routes

node_identifier = str(uuid4()).replace('-', '')

blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender', 'recipient', 'amount', 'password']
    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], values['password'])

    if index is not None:
        response = {'message': f'Transaction will be added to Block {index}'}
    else:
        response = {'message': 'Transaction failed. Invalid sender, recipient, or insufficient funds.'}
    
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)
        print(node)


    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200
@app.route('/')
def index():

    register_nodes_on_start(port)
    users = blockchain.get_user_list()

    # Create a dictionary to store user balances
    user_balances = {}
    for user in users:
        balance = blockchain.get_user_balance(user)
        user_balances[user] = balance

    return render_template('index.html', users=users, user_balances=user_balances)

@app.route('/register_user', methods=['POST'])
def register_user():
    global port
    values = request.get_json()

    required = ['username', 'password']
    if not all(k in values for k in required):
        return 'Missing values', 400

    username = values['username']
    password = values['password']

    user_id = blockchain.register_user(username, password)

    if user_id is not None:
        response = {'message': f'User {username} registered with ID: {user_id}'}
        # Broadcast the updated user list to other nodes
        for node in blockchain.nodes:
            if node != f'127.0.0.1:{port}':  # Exclude the current node
                update_url = f'http://{node}/update_user_list'
                requests.post(update_url, json={'users': blockchain.users})
    else:
        response = {'message': f'User {username} already exists.'}

    return jsonify(response), 200


@app.route('/get_user_list', methods=['GET'])
def get_user_list():
    users = blockchain.get_user_list()
    response = {'users': users}
    return jsonify(response), 200

@app.route('/update_user_list', methods=['POST'])
def update_user_list():
    values = request.get_json()
    users = values.get('users')

    if users is not None:
        blockchain.update_user_list(users)

    return jsonify({'message': 'User list updated'}), 200

@app.route('/get_user_balances', methods=['GET'])
def get_user_balances():
    users = blockchain.get_user_list()
    user_balances = {}

    for user in users:
        balance = blockchain.get_user_balance(user)
        user_balances[user] = balance

    response = {'user_balances': user_balances}
    return jsonify(response), 200
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    

    app.run(host='127.0.0.1', port=port)
