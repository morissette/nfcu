"""
Alexa Skill for Getting Navy Federal Credit Union Account Data
"""
import os

import nfcu


def _build_speechlet_response(title, output, reprompt_text, should_end_session):
    return {
        "outputSpeech": {"type": "PlainText", "text": output},
        "card": {
            "type": "Simple",
            "title": f"SessionSpeechlet - {title}",
            "content": f"SessionSpeechlet - {output}",
        },
        "reprompt": {"outputSpeech": {"type": "PlainText", "text": reprompt_text}},
        "shouldEndSession": should_end_session,
    }


def _build_response(session_attributes, speechlet_response):
    return {
        "version": "1.0",
        "sessionAttributes": session_attributes,
        "response": speechlet_response,
    }


def _get_welcome_response():
    return _build_response(
        {},
        _build_speechlet_response(
            "Welcome",
            "Do you want to check your balance?",
            "Do you want to check your balance?",
            True,
        ),
    )


def _get_account_summary():
    username = os.environ["NFCU_USERNAME"]
    password = os.environ["NFCU_PASSWORD"]

    api = nfcu.NFCU(username, password)
    data = api.get_account_summary()

    total = sum(
        item["totalBalance"]
        for item in data["accountSummary"]["data"]["accountCategories"]
    )

    speech_output = f"Your total account balance is ${total:.2f}"
    return _build_response(
        {},
        _build_speechlet_response("AccountSummary", speech_output, speech_output, True),
    )


def _handle_session_end():
    return _build_response(
        {},
        _build_speechlet_response("Session Ended", "Bye now.", None, True),
    )


def on_session_started(session_started_request, session):
    """Called when the session starts."""
    print(
        f"on_session_started requestId={session_started_request['requestId']}, "
        f"sessionId={session['sessionId']}"
    )


def on_launch(launch_request, session):
    """Called when the user launches the skill without specifying what they want."""
    print(
        f"on_launch requestId={launch_request['requestId']}, "
        f"sessionId={session['sessionId']}"
    )
    return _get_welcome_response()


def on_intent(intent_request, session):
    """Called when the user specifies an intent for this skill."""
    print(
        f"on_intent requestId={intent_request['requestId']}, "
        f"sessionId={session['sessionId']}"
    )

    intent_name = intent_request["intent"]["name"]

    handlers = {
        "GetAccountSummary": _get_account_summary,
        "AMAZON.HelpIntent": _get_welcome_response,
        "AMAZON.CancelIntent": _handle_session_end,
        "AMAZON.StopIntent": _handle_session_end,
    }

    handler = handlers.get(intent_name)
    if handler is None:
        raise ValueError(f"Unrecognised intent: {intent_name}")
    return handler()


def on_session_ended(session_ended_request, session):
    """Called when the user ends the session."""
    print(
        f"on_session_ended requestId={session_ended_request['requestId']}, "
        f"sessionId={session['sessionId']}"
    )


def lambda_handler(event, context):  # noqa: ARG001
    """
    Route the incoming request based on type
    (LaunchRequest, IntentRequest, etc.).
    The JSON body of the request is provided in the event parameter.
    """
    print(
        f"event.session.application.applicationId="
        f"{event['session']['application']['applicationId']}"
    )

    if event["session"]["new"]:
        on_session_started(
            {"requestId": event["request"]["requestId"]},
            event["session"],
        )

    request_type = event["request"]["type"]
    if request_type == "LaunchRequest":
        return on_launch(event["request"], event["session"])
    if request_type == "IntentRequest":
        return on_intent(event["request"], event["session"])
    if request_type == "SessionEndedRequest":
        return on_session_ended(event["request"], event["session"])
