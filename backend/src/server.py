import os
import slack
import certifi
import ssl
from flask import Flask, request
from flask_cors import CORS, cross_origin
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)

CORS(app, support_credentials=True)

ssl_context = ssl.create_default_context(cafile=certifi.where())

SLACK_API_TOKEN = os.environ['SLACK_BOT_TOKEN']

client = slack.WebClient(token=SLACK_API_TOKEN, ssl=ssl_context)

def send_message_slack(fullname_arg: str, emailaddress_arg: str, cloud_pak_arg: str, gaia_arg: str, op_arg: str ):
    data = {
            'Full Name':fullname_arg,
            'Email Address':emailaddress_arg,
            'Cloud Pak':cloud_pak_arg,
            'GAIA':gaia_arg,
            'Opportunity Description':op_arg
        }
    client.chat_postMessage(channel="website-app",text=data)

class SendMessage(Resource):
    def post(self):
        data = request.json
        fullname: str = data['fullname']
        emailaddress: str = data['emailaddress']
        cloud_pak: str = data['cloudpakvalue']
        gaia: set = data['gaia']
        opportunity_description: str = data['requestdescription']
        try:
            send_message_slack(fullname, emailaddress, cloud_pak, gaia, opportunity_description)
            return True
        except Exception as identifier:
            return identifier

api.add_resource(SendMessage,'/api/v1/sendmessage/')
