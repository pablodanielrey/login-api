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

    def __init__(self, oidc_host='http://hydra:4445', oidc_client='', oidc_secret='', verify=False):
        self.verify = verify
        self.host = oidc_host
        self.client = oidc_client
        self.secret = oidc_secret
        self.grant = ClientCredentialsGrant(self.client, self.secret, verify=self.verify)

    def _obtener_token(self):
        token = self.grant.get_token(self.grant.access_token(scopes=['hydra.consent']))
        if not token:
            raise Exception('error obteniendo token de acceso')
        return token

    def obtener_consent(self, consent_id, token=None):
        if not token:
            token = self._obtener_token()
        url = '{}/oauth2/consent/requests/{}'.format(self.host,consent_id)
        headers = {
            'Authorization': 'bearer {}'.format(token),
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        r = requests.get(url, verify=self.verify, headers=headers, allow_redirects=False)
        if not r.ok:
            return None
        return r.json()

    def aceptar_consent(self, consent):
        pass

    def denegar_consent(self, consent):
        pass

    def chequear_login_challenge(self, challenge):
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
        r = requests.get(url, verify=self.verify, allow_redirects=False)
        if not r.ok:
            logging.debug(r)
            raise Exception('error chequeando login challenge')

        login = r.json()
        return login
        """
        if login['skip']:
            redireccion = self._aceptar_login_challenge(challenge, login)
        """

    def _aceptar_login_challenge(self, challenge, login_request):
        url = '{}/oauth2/auth/requests/login/{}/accept'.format(self.host, challenge)
        data = {
            'subject': login_request['subject'],
            'remember': True,
            'remember_for': 3600,
            'acr':''
        }
        h = {
            'Content-Type': 'application/json'
        }
        r = requests.put(url, headers=h, json=data, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception('error aceptando el challenge de login')
        response = r.json()
        return response.redirect_to

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
        return response.redirect_to