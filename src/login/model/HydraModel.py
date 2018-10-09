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

    def aceptar_consent_challenge(self, challenge, data):
        url = '{}/oauth2/auth/requests/consent/{}/accept'.format(self.host, challenge)
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
        return response

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
        return response

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
            raise Exception(r.json())

        login = r.json()    
        logging.debug(login)
        return login

    def aceptar_login_challenge(self, challenge, data):
        url = '{}/oauth2/auth/requests/login/{}/accept'.format(self.host, challenge)
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
        return response

    def denegar_login_challenge(self, challenge, data):
        url = '{}/oauth2/auth/requests/login/{}/reject'.format(self.host, challenge)
        h = {
            'X-Forwarded-Proto':'https',
            'Content-Type': 'application/json'
        }
        r = requests.put(url, headers=h, json=data, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception('error denegando el challenge de login')
        response = r.json()
        return response


    """
        métodos de administración de hydra. para la aplicación de administracion
    """

    def obtener_consent_sesiones(self, uid):
        url = '{}/oauth2/auth/sessions/consent/{}'.format(self.host, uid)
        h = {
            'X-Forwarded-Proto':'https',
            'Content-Type': 'application/json'
        }
        r = requests.get(url, headers=h, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception(r.status_code)
        response = r.json()
        return response        

    def eliminar_sesiones_usuario(self, uid):
        url = '{}/oauth2/auth/sessions/consent/{}'.format(self.host, uid)
        h = {
            'X-Forwarded-Proto':'https',
            'Content-Type': 'application/json'
        }
        r = requests.delete(url, headers=h, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception(r.status_code)

    def eliminar_sesiones_cliente_usuario(self, cid, uid):
        url = '{}/oauth2/auth/sessions/consent/{}/{}'.format(self.host, uid, cid)
        h = {
            'X-Forwarded-Proto':'https',
            'Content-Type': 'application/json'
        }
        r = requests.delete(url, headers=h, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception(r.status_code)

    def eliminar_sesion_login_usuario(self, uid):
        url = '{}/oauth2/auth/sessions/login/{}'.format(self.host, uid)
        h = {
            'X-Forwarded-Proto':'https',
            'Content-Type': 'application/json'
        }
        r = requests.delete(url, headers=h, verify=self.verify)
        if not r.ok:
            logging.debug(r)
            raise Exception(r.status_code)
        return r.text
