import datetime
import hashlib
import json
from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, padding


class User:
    def __init__(self, user_id, port_id):
        self.private_key, self.public_key = self.generate_key_pair()
        self.blockchain = Blockchain()
        self.known_users = []
        self.user_id = user_id
        self.port_id = port_id

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
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
        self.create_block(proof=1, previous_hash="0")

    def create_block(self, proof, previous_hash):
        block = {
            "index": len(self.chain) + 1,
            "timestamp": str(datetime.datetime.now()),
            "proof": proof,
            "previous_hash": previous_hash,
            "transactions": self.current_transactions,
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
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
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
                str(new_proof**2 - previous_proof**2).encode()
            ).hexdigest()
            if hash_operation[:5] == "00000":
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    def hash(self, block):
        def convert_keys_to_str(obj):
            if isinstance(obj, bytes):
                return obj.decode("utf-8")
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
            if block["previous_hash"] != self.hash(previous_block):
                return False

            previous_proof = previous_block["proof"]
            proof = block["proof"]
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()
            ).hexdigest()

            if hash_operation[:5] != "00000":
                return False
            previous_block = block
            block_index += 1

        return True


import requests

app = Flask(__name__)
users = {}
ports = [5000]


def broadcast_ports():
    # Broadcast the updated list to all known nodes
    for port in ports:
        url = f"http://127.0.0.1:{port}/update_ports"
        data = {"ports": ports}
        requests.post(url, json=data)

def broadcast_users():
    # Broadcast the updated list to all known nodes
    for port in ports:
        url = f"http://127.0.0.1:{port}/update_users"
        data = {"users": users}
        requests.post(url, json=data)
def broadcast_new_user(new_user):
    # Broadcast the new port to all known nodes
    for port in ports:
        if port != 5000:  # Avoid broadcasting to itself
            url = f"http://127.0.0.1:{port}/update_new_user"
            data = {"new_user": new_user}
            requests.post(url, json=data)

def broadcast_new_port(new_port):
    # Broadcast the new port to all known nodes
    for port in ports:
        if port != 5000:  # Avoid broadcasting to itself
            url = f"http://127.0.0.1:{port}/update_new_port"
            data = {"new_port": new_port}
            requests.post(url, json=data)


@app.route("/process_new_port", methods=["POST"])
def process_new_port():
    new_port = request.json.get("new_port")

    if new_port and isinstance(new_port, int):
        # Append the new port to the current list
        ports.append(new_port)
        # Broadcast the updated list
        broadcast_ports()
        # Broadcast the new port to all nodes
        broadcast_new_port(new_port)
        return f"Port {new_port} processed successfully"

    return "Invalid port provided", 400

@app.route("/register_port", methods=["POST"])
def register_port():
    new_port = request.json.get("port")

    if new_port and isinstance(new_port, int):
        # Send the new port to 5000
        url_5000 = "http://127.0.0.1:5000/process_new_port"
        data_5000 = {"new_port": new_port}
        requests.post(url_5000, json=data_5000)

        return f"Port {new_port} registered successfully"

    return "Invalid port provided", 400

@app.route("/update_ports", methods=["POST"])
def update_ports():
    updated_ports = request.json.get("ports")

    if updated_ports and isinstance(updated_ports, list):
        global ports
        # Replace the current list with the updated list
        ports = updated_ports
        return "Ports updated successfully"

    return "Invalid ports list provided", 400

@app.route("/update_users", methods=["POST"])
def update_users():
    update_users = request.json.get("users")

    if update_users:
        global users
        # Replace the current list with the updated list
        users = update_users
        return "Users updated successfully"

    return "Invalid user list provided", 400

@app.route("/ports", methods=["GET"])
def get_ports():
    return {"ports": ports}
@app.route("/users", methods=["GET"])
def get_users():
    return {"users": users}

@app.route("/process_new_user", methods=["POST"])
def process_new_user():
    port_id = request.json.get("port_id")
    user_id = request.json.get("user_id")
    if user_id and port_id:
        # Append the new port to the current list
        users[user_id] = port_id
        # Broadcast the updated list
        broadcast_users()
        # Broadcast the new port to all nodes
        broadcast_new_user(users)


        return f"User {user_id} processed successfully"

    return "Invalid port provided", 400


@app.route("/users/register", methods=["POST"])
def register_user():
    data = request.get_json()
    user_id = data.get("user_id")
    port_id = data.get("port_id")
    if user_id and port_id:
        new_user = User(user_id,port_id)
        url_5000 = "http://127.0.0.1:5000/process_new_user"
        data_5000 = {"port_id": port_id, "user_id": user_id}
        requests.post(url_5000, json=data_5000)
        

        for existing_user_id, existing_user in users.items():
            if isinstance(existing_user, User) and existing_user_id != user_id:
                existing_user.add_known_user(user_id)

        return (
            jsonify(
                {
                    "message": f"User {user_id} registered successfully",
                    "known_users": new_user.get_known_users(),
                }
            ),
            201,
        )
    else:
        return (
            jsonify({"message": "User registration failed. Provide a valid user_id."}),
            400,
        )


@app.route("/add_transaction/<user_id>", methods=["POST"])
def add_transaction(user_id):
    data = request.get_json()

    required_fields = ["sender", "recipient", "amount"]
    if not all(field in data for field in required_fields):
        return "Missing fields", 400

    user = users.get(user_id)
    sender = users.get(data["recipient"])
    if not user or not sender:
        return jsonify({"message": "User not found"}), 404
    if data["sender"] == user_id:
        user.blockchain.create_transaction(
            data["sender"], data["recipient"], data["amount"], user.public_key
        )
        response = {"message": "Transaction added to current transactions"}
        print(user.blockchain.current_transactions)
        return jsonify(response), 201
    else:
        response = {"message": "Sender is not equal to user_id"}
        return jsonify(response), 400


@app.route("/broadcast_transaction/<user_id>", methods=["POST"])
def broadcast_transaction(user_id):
    data = request.get_json()

    required_fields = ["sender", "recipient", "amount"]
    if not all(field in data for field in required_fields):
        return "Missing fields", 400

    user = users.get(user_id)
    sender = users.get(data["recipient"])

    if not user or not sender:
        return jsonify({"message": "User not found"}), 404
    if data["sender"] == user_id:
        user.blockchain.create_transaction(
            data["sender"], data["recipient"], data["amount"], user.public_key
        )
    else:
        return

    for user_id in user.get_known_users():
        if (
            sender != user_id
        ):  # Skip broadcasting to the user who initiated the transaction
            user = users.get(user_id)
            user.blockchain.create_transaction(
                data["sender"], data["recipient"], data["amount"], sender.public_key
            )
            print(user.blockchain.current_transactions)

    # Response to the client
    response = {"message": "Transaction added and broadcasted successfully"}
    return jsonify(response), 201


@app.route("/get_current_transaction/<user_id>", methods=["GET"])
def get_current_transaction(user_id):
    user = users.get(user_id)
    print(user.blockchain.current_transactions)
    response = {"message": "current list"}
    return jsonify(response), 201


@app.route("/mine_block/<user_id>", methods=["GET"])
def mine_block(user_id):
    user = users.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    previous_block = user.blockchain.last_block
    previous_proof = previous_block["proof"]
    proof = user.blockchain.proof_of_work(previous_proof)
    previous_hash = user.blockchain.hash(previous_block)
    user.blockchain.create_block(proof, previous_hash)

    for user_id, user in users.items():
        # Collect all chains for comparison
        all_chains = [u.blockchain.chain for u in users.values()]

        # Find the longest valid chain
        longest_chain = max(
            filter(user.blockchain.chain_valid, all_chains), key=len, default=None
        )

        # Update the user's chain with the longest valid chain
        if longest_chain:
            user.blockchain.chain = longest_chain

    response = {
        "message": "A block is MINED",
        "index": user.blockchain.last_block["index"],
        "timestamp": user.blockchain.last_block["timestamp"],
        "proof": user.blockchain.last_block["proof"],
        "previous_hash": user.blockchain.last_block["previous_hash"],
        "transactions": str(
            user.blockchain.last_block["transactions"]
        ),  # Convert bytes to string
    }

    return jsonify(response), 200


@app.route("/get_chain/<user_id>", methods=["GET"])
def display_chain(user_id):
    user = users.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    def convert_keys_to_str(obj):
        if isinstance(obj, bytes):
            return obj.decode("utf-8")
        elif isinstance(obj, dict):
            return {
                convert_keys_to_str(k): convert_keys_to_str(v) for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [convert_keys_to_str(elem) for elem in obj]
        else:
            return obj

    response = {
        "chain": convert_keys_to_str(user.blockchain.chain),
        "length": len(user.blockchain.chain),
    }

    return jsonify(response), 200


if __name__ == "__main__":
    app.run(host="localhost", port=5000, debug=True)
