import os
from flask import Flask
from flask_restful import Api, Resource
import slack
import certifi
import ssl

app = Flask(__name__)
api = Api(app)

ssl_context = ssl.create_default_context(cafile=certifi.where())
SLACK_API_TOKEN = os.environ['SLACK_BOT_TOKEN']

client = slack.WebClient(token=SLACK_API_TOKEN, ssl=ssl_context)

def send_message_slack(fullname_arg: str, emailaddress_arg: str, gaia_arg: str, op_arg: str ):
    data = {
            'Full Name':fullname_arg,
            'Email Address':emailaddress_arg,
            'GAIA':gaia_arg,
            'Opportunity Description':op_arg
        }
    client.chat_postMessage(
        channel="website-app",
        text=data
    )

class SendMessage(Resource):
    def get(self, fullname_input, emailaddress_input, gaia_input, op_input):
        send_message_slack(fullname_input, emailaddress_input, gaia_input, op_input)
        return "OK"

api.add_resource(SendMessage,'/api/v1/sendmessage/<string:fullname_input>/<string:emailaddress_input>/<string:gaia_input>/<string:op_input>')