import ast
import jwt
import requests
import secrets
import datetime
import logging
from gslauth import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render

logger = logging.getLogger('gslauth.models')

def logindotgov(request):
    msg = "   logindotgov request: " + str(request)
    logger.info(msg)

    if 'logindotgov' in str(request):

        login = 'https://idp.int.identitysandbox.gov/openid_connect/authorize?'
        login = login + "acr_values=" + settings.LOGINDOTGOV_ACR + "&"
        login = login + "client_id=" + settings.LOGINDOTGOV_CLIENT_ID + "&"
        login = login + "nonce=" + str(secrets.token_urlsafe(30)) + "&"
        login = login + "prompt=select_account&"
        login = login + "redirect_uri=" + settings.LOGINDOTGOV_RETURN_TO + "&"
        login = login + "response_type=code&"
        login = login + "scope=" + settings.LOGINDOTGOV_SCOPE + "&"
        login = login + "state=" + settings.LOGINDOTGOV_LOGIN_STATE

        msg = '   logindotgov login HttpResponseRedirect( ' + str(login) + ' )'
        logger.info(msg)
        return HttpResponseRedirect(login)
    else:
        return HttpResponseRedirect("/static/oops.html")

def logindotgov_authenticated(request):
    #msg = "   logindotgov request: " + str(request)
    #logger.info(msg)
    #msg = "               session keys: " + str(request.session.keys())
    #logger.info(msg)
    state = None
    if 'code' in str(request):
        try:
            code = request.GET['code']
            state = request.GET['state']
            #msg = "   code: " + code
            #logger.info(msg)
            #msg = "   state: " + state
            #logger.info(msg)
        except KeyError:
            msg = "    KeyError request.session: " + str(request)
            logger.info(msg)

    if str(state) == settings.LOGINDOTGOV_LOGIN_STATE:
        tokenurl = settings.LOGINDOTGOV_IDP_SERVER + "/api/openid_connect/token"

        expires = int(datetime.datetime.utcnow().strftime('%s')) + int(settings.JWTEXP)

        assertion = {}
        assertion["iss"] = str(settings.LOGINDOTGOV_CLIENT_ID)
        assertion["sub"] = str(settings.LOGINDOTGOV_CLIENT_ID)
        assertion["aud"] = str(tokenurl)
        assertion["jti"] = str(secrets.token_urlsafe(settings.JWTSAFELEN))
        assertion["exp"] = str(expires)

        #msg = "   assertion: " + str(assertion)
        #logger.info(msg)

        signedassertion = jwt.encode(assertion, settings.LOGINDOTGOV_PRIVATE_CERT, algorithm="RS256")  
        data = "client_assertion_type=" + settings.LOGINDOTGOV_CLIENT_ASSERTION_TYPE + "&"
        data = data + "client_assertion=" + str(signedassertion) + "&"
        data = data + "code=" + str(code) + "&"
        data = data + "grant_type=authorization_code"

        proxies = {}
        proxies["http"] = str(settings.HTTP_PROXY)
        proxies["https"] = str(settings.HTTP_PROXY)

        #msg = "   tokenurl: " + str(tokenurl)
        #logger.info(msg)
        #msg = "       data: " + str(data)
        #logger.info(msg)

        #curlcmd = 'curl -v -x ' + settings.HTTP_PROXY + ' -d "' + str(data) + '" ' + tokenurl
        #logger.info(curlcmd)

        tokenresponse = requests.post(url=tokenurl, data=data, proxies=proxies)
        msg = "   tokenresponse: " + tokenresponse.text
        logger.info(msg)

        ale = ast.literal_eval(tokenresponse.text)
        msg = "  ale: " + str(ale)
        logger.info(msg)

        accesstoken = ale['access_token']
        #msg = "  accesstoken: " + str(accesstoken)
        #logger.info(msg)

        infourl = settings.LOGINDOTGOV_IDP_SERVER + "/api/openid_connect/userinfo"

        # curl headers need str vs {} for requests.get
        #cheaders = "Authorization: Bearer " + str(accesstoken)
        #curlcmd = 'curl -v -x ' + settings.HTTP_PROXY + '  -H "' + cheaders + '" ' + infourl
        #logger.info(curlcmd)

        headers = {}
        headers["Authorization"] = "Bearer " + str(accesstoken)
        userattributes = requests.get(infourl, proxies=proxies, headers=headers)

        attributes = []
        attstr = userattributes.text
        msg = "   attstr: " + attstr
        logger.info(msg)
   
        # The returned attributes string is UGLY -- it looks like a {}, but it is not a valid string which can be easily be manipulated using ast.
        # It requires all of the str manipulation below to return a list tuples with clean values
        # attstr: {"sub":"cb081269-23a7-47ad-b6c2-9f0b79a33dc2","iss":"https://idp.int.identitysandbox.gov/","email":"kirk.l.holub@noaa.gov","email_verified":true,"given_name":"FAKEY","family_name":"MCFAKERSON","birthdate":"1938-10-06","verified_at":1667325527} 
        # I suspect the issue is a lack of double quotes surrounding the "verified_at" integer value.  Regardless, str manipulation is required.
        for attr in attstr.split(','):
            attr = attr.replace('{', '')
            attr = attr.replace('}', '')
            #msg = "   attr = " + str(attr)
            #logger.info(msg)

            v = str(attr).split(':')
            #msg = "    v = " + str(v)
            #logger.info(msg)

            key = str(v[0]).replace('"', '', 10)
            value = str(v[1]).replace('"', '', 10)
            if len(v) > int(2):
                value = value + ':' + str(v[2]).replace('"', '', 10)
            attributes.append((key, str(value)))

        msg = "    attributes: " + str(attributes)
        logger.info(msg)

        return render(request, 'attrs.html',
                  {'paint_logout': True,
                   'attributes': attributes})
    else:
        msg = " state is not login state: " + str(state)
        logger.info(msg)

    return HttpResponseRedirect(settings.LOGINDOTGOV_ERROR_REDIRECT)

def logout(request):
    msg = "   logout request: " + str(request)
    logger.info(msg)

    if 'logout' in str(request):

        logout = settings.LOGINDOTGOV_IDP_SERVER + '/openid_connect/logout?'
        logout = logout + "client_id=" + settings.LOGINDOTGOV_CLIENT_ID + "&"
        logout = logout + "post_logout_redirect_uri=" + settings.LOGINDOTGOV_LOGOUT_URI + "&"
        logout = logout + "state=" + settings.LOGINDOTGOV_LOGOUT_STATE

        msg = '   logout HttpResponseRedirect( ' + str(logout) + ' )'
        logger.info(msg)
        return HttpResponseRedirect(logout)
    else:
        return HttpResponseRedirect("/static/oops.html")

def index(request):
    return HttpResponseRedirect(settings.LOGINDOTGOV_AUTHENTICATED_REDIRECT)
