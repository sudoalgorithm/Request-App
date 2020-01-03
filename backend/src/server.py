import os
from flask import Flask
from flask_restful import Api, Resource
import slack

app = Flask(__name__)
api = Api(app)

SLACK_API_TOKEN = os.environ['SLACK_BOT_TOKEN']

client = slack.WebClient(token=SLACK_API_TOKEN)

def send_message_slack():
    client.chat_postMessage(
        channel="website-app",
        text="Hello from your app! :tada:",
    )

class SendMessage(Resource):
    def get(self):
        send_message_slack()
        return "OK"

api.add_resource(SendMessage,'/api/v1/sendmessage/')