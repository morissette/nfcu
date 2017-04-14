"""
Alexa Skill for Getting
Navy Federal Credit Union
Account Data
"""
from __future__ import print_function
import nfcu


def build_speechlet_response(title, output, reprompt_text, should_end_session):
    """
    Build alexa speechlet response
    """
    return {
        'outputSpeech': {
            'type': 'PlainText',
            'text': output
        },
        'card': {
            'type': 'Simple',
            'title': "SessionSpeechlet - " + title,
            'content': "SessionSpeechlet - " + output
        },
        'reprompt': {
            'outputSpeech': {
                'type': 'PlainText',
                'text': reprompt_text
            }
        },
        'shouldEndSession': should_end_session
    }


def build_response(session_attributes, speechlet_response):
    """
    Build response for Alexa
    """
    return {
        'version': '1.0',
        'sessionAttributes': session_attributes,
        'response': speechlet_response
    }


def get_welcome_response():
    """
    Set welcome message from alexa
    """
    session_attributes = {}
    card_title = "Welcome"
    speech_output = "Do you want to check your balance?"

    # If the user either does not reply to the
    # welcome message or says something
    # that is not understood, they will be prompted
    # again with this text.
    reprompt_text = "Do you want to check your balance?"

    should_end_session = True
    return build_response(session_attributes, build_speechlet_response(
        card_title, speech_output, reprompt_text, should_end_session))


def get_account_summary():
    """
    Get all balances
    """
    session_attributes = {}
    card_title = "AccountSummary"

    # Calculate Total in All Accounts
    access_number, password = 1, 2

    api = nfcu.NFCU(access_number, password)
    data = api.get_account_summary()

    total = 0
    for item in data["accountSummary"]["data"]["accountCategories"]:
        total += item["totalBalance"]

    speech_output = "Your total account balance is ${total}".format(
        total=total)

    reprompt_text = speech_output
    should_end_session = True

    return build_response(session_attributes, build_speechlet_response(
        card_title, speech_output, reprompt_text, should_end_session))


def get_specific_account_balance():
    """
    Get specific account balance
    """
    session_attributes = {}
    card_title = "AccountDetailedSummary"

    # Calculate Total in All Accounts
    access_number, password = 1, 2

    api = nfcu.NFCU(access_number, password)
    data = api.get_account_summary()
    total = 0
    for item in data["accountSummary"]["data"]["accountCategories"]:
        total += item["totalBalance"]

    speech_output = "Your total account balance is ${total}".format(
        total=total)

    reprompt_text = speech_output
    should_end_session = True

    return build_response(session_attributes, build_speechlet_response(
        card_title, speech_output, reprompt_text, should_end_session))


def handle_session_end_request():
    """
    Set alexa response on close app
    """
    card_title = "Session Ended"
    speech_output = "Bye now."

    # Setting this to true ends the session and exits the skill.
    should_end_session = True
    return build_response({}, build_speechlet_response(
        card_title, speech_output, None, should_end_session))


# --------------- Events ------------------
def on_session_started(session_started_request, session):
    """
    Called when the session starts
    """

    print("on_session_started requestId=" +
          session_started_request['requestId'] +
          ", sessionId=" + session['sessionId'])


def on_launch(launch_request, session):
    """
    Called when the user launches the skill
    without specifying what they want
    """

    print("on_launch requestId=" + launch_request['requestId'] +
          ", sessionId=" + session['sessionId'])
    # Dispatch to your skill's launch
    return get_welcome_response()


def on_intent(intent_request, session):
    """
    Called when the user specifies an intent for this skill
    """

    print("on_intent requestId=" + intent_request['requestId'] +
          ", sessionId=" + session['sessionId'])

    intent_name = intent_request['intent']['name']

    # Dispatch to your skill's intent handlers
    if intent_name == "GetAccountSummary":
        return get_account_summary()
    elif intent_name == "AMAZON.HelpIntent":
        return get_welcome_response()
    elif intent_name == "AMAZON.CancelIntent" or \
            intent_name == "AMAZON.StopIntent":
        return handle_session_end_request()
    else:
        raise ValueError("Invalid intent")


def on_session_ended(session_ended_request, session):
    """
    Called when the user ends the session.
    Is not called when the skill
    :return: should_end_session=true
    """
    print("on_session_ended requestId=" + session_ended_request['requestId'] +
          ", sessionId=" + session['sessionId'])
    # add cleanup logic here


# --------------- Main handler ------------------
def lambda_handler(event):
    """
    Route the incoming request based on type
    (LaunchRequest, IntentRequest, etc.)
    The JSON body of the request is provided in the event parameter.
    """
    print("event.session.application.applicationId=" +
          event['session']['application']['applicationId'])

    """
    Uncomment this if statement and populate with
    your skill's application ID to prevent someone
    else from configuring a skill that sends requests to this
    function.
    """
    # if (event['session']['application']['applicationId'] !=
    #         "amzn1.echo-sdk-ams.app.[unique-value-here]"):
    #     raise ValueError("Invalid Application ID")

    if event['session']['new']:
        on_session_started(
            {
                'requestId': event['request']['requestId']
            },
            event['session']
        )

    if event['request']['type'] == "LaunchRequest":
        return on_launch(event['request'], event['session'])
    elif event['request']['type'] == "IntentRequest":
        return on_intent(event['request'], event['session'])
    elif event['request']['type'] == "SessionEndedRequest":
        return on_session_ended(event['request'], event['session'])
