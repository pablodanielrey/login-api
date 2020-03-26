import os

EMAILS_API_URL = os.environ['EMAILS_API_URL']

from login.model.LoginModel import LoginModel
from login_api.model.MailsModel import MailsModel
from login_api.model.EventsModel import EventsModel

loginModel = LoginModel()
mailsModel = MailsModel(EMAILS_API_URL)
eventsModel = EventsModel()