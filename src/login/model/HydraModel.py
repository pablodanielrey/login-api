"""
    implementa la api de hydra.
    referencia :
    https://www.ory.sh/docs/api/hydra/?version=latest
    https://www.ory.sh/docs/guides/master/hydra/3-overview/1-oauth2#implementing-a-login--consent-provider
"""
import logging
import requests

from oidc.oidc import ClientCredentialsGrant

class HydraModel:

    def __init__(self, oidc_host, verify=False):
        self.verify = verify
        self.host = oidc_host

    def obtener_consent_challenge(self, challenge):
        """
            llamada a :
                GET /oauth2/auth/requests/consent/{challenge}
            retorno:
               {
                   challenge: string
                   client: {}
                   oidc_context: {}
                   request_url: string
                   requested_scope: [string]
                   skip: boolean
                   subject: string
               } 
        """
        url = '{}/oauth2/auth/requests/consent/{}'.format(self.host, challenge)
        h = {
            'X-Forwarded-Proto':'https'
        }
        r = requests.get(url, headers=h, verify=self.verify, allow_redirects=False)
        if not r.ok:
            logging.debug(r)
            raise Exception('error chequeando login challenge')

        consent = r.json()
        logging.debug(consent)
        return consent

    def aceptar_consent_challenge(self, challenge, consent):
        url = '{}/oauth2/auth/requests/consent/{}/accept'.format(self.host, challenge)
        data = {
            'grant_scope': consent['requested_scope'],
            'remember': False if consent['skip'] else True,
            'remember_for': 3600,
            'session':{
                'access_token':{},
                'id_token':{}
            }
        }
        h = {
            'X-Forwarded-Proto':'https',
            'Content-Type': 'application/json'
        }
        r = requests.put(url, headers=h, json=data, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception('error aceptando el challenge de consent')
        response = r.json()
        logging.debug(response)
        return response['redirect_to']

    def denegar_consent_challenge(self, challenge):
        url = '{}/oauth2/auth/requests/consent/{}/reject'.format(self.host, challenge)
        data = {
            'error':'id_del_error',
            'error_description': 'descripción del error'
        }
        h = {
            'Content-Type': 'application/json'
        }
        r = requests.put(url, headers=h, json=data, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception('error denegando el challenge de login')
        response = r.json()
        return response['redirect_to']

    def obtener_login_challenge(self, challenge):
        """
            llamada a :
                GET /oauth2/auth/requests/login/{challenge}
            retorno:
               {
                   challenge: string
                   client: {}
                   oidc_context: {}
                   request_url: string
                   requested_scope: [string]
                   skip: boolean
                   subject: string
               } 
        """
        url = '{}/oauth2/auth/requests/login/{}'.format(self.host, challenge)
        h = {
            'X-Forwarded-Proto':'https'
        }
        r = requests.get(url, headers=h, verify=self.verify, allow_redirects=False)
        if not r.ok:
            logging.debug(r)
            raise Exception('error chequeando login challenge')

        login = r.json()    
        logging.debug(login)
        return login
        """
        if login['skip']:
            redireccion = self._aceptar_login_challenge(challenge, login)
        """

    def aceptar_login_challenge(self, challenge, login_request):
        url = '{}/oauth2/auth/requests/login/{}/accept'.format(self.host, challenge)
        data = {
            'subject': login_request['subject'],
            'remember': False if login_request['skip'] else True,
            'remember_for': 3600,
            'acr':''
        }
        h = {
            'X-Forwarded-Proto':'https',
            'Content-Type': 'application/json'
        }
        r = requests.put(url, headers=h, json=data, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception('error aceptando el challenge de login')
        response = r.json()
        logging.debug(response)
        return response['redirect_to']

    def _denegar_login_challenge(self, challenge, login_request):
        url = '{}/oauth2/auth/requests/login/{}/reject'.format(self.host, challenge)
        data = {
            'error':'id_del_error',
            'error_description': 'descripción del error'
        }
        h = {
            'Content-Type': 'application/json'
        }
        r = requests.put(url, headers=h, json=data, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception('error denegando el challenge de login')
        response = r.json()
        return response['redirect_to']