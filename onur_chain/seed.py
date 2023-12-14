from flask import Flask, request, jsonify
from flask import app

import requests

app = Flask(__name__)

active_nodes = set()


def broadcast():
   pass


@app.route("/nodes/signin", methods=["POST"])
def sign_nodes():
    values = request.get_json()

    url = values.get("url")
    if url is None:
        return "Error: Please supply a valid port number", 400
    
    active_nodes.add(url)
    
    for node in active_nodes:
        if url != node:
            payload = {
                        "nodes": list(url)
            }
            requests.post(f'{node}/nodes/register', json=payload)
    
    response = {
        'message': f'Port {url} has been added'
    }
    
    return jsonify(response), 201


@app.route("/nodes/signout", methods=["POST"])
def signout_nodes():
    pass


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
