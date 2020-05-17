#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
import re
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class BaseField(object):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=None):
        self.required = required
        self.nullable = nullable
        self.type_check = type_check
        self._value = None

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, _value):
        if self.type_check and \
           not isinstance(_value, self.type_check):
            raise ValueError("Value: {} must be type: {} but it {}"
                             .format(_value, self.type_check, type(_value)))
        self._value = _value


class CharField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=unicode):
        super(CharField, self).__init__(name, required, nullable, type_check)


class ArgumentsField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=dict):
        super(ArgumentsField, self).__init__(name,
                                             required,
                                             nullable,
                                             type_check)


# Здесь не понял зачем наследование от CharField
# class EmailField(CharField):
class EmailField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=unicode):
        super(EmailField, self).__init__(name, required, nullable, type_check)

    @property
    def value(self):
        super(EmailField, self).value

    @value.setter
    def value(self, _value):
        if _value and not ('@' in _value):
            raise ValueError("must be @ in the address {}".format(_value))
        self._value = _value


class PhoneField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=unicode):
        super(PhoneField, self).__init__(name, required, nullable, type_check)

    @property
    def value(self):
        super(PhoneField, self).value

    @value.setter
    def value(self, _value):
        if not isinstance(_value, (unicode, str)):
            raise ValueError("must be str or int {}".format(_value))
        if not re.match(r'^7.{10}$', str(_value)):
            raise ValueError("must be 10 digits".format(_value))
        self._value = _value


class DateField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=str):
        super(DateField, self).__init__(name, required, nullable, type_check)

    @property
    def value(self):
        super(DateField, self).value

    @value.setter
    def value(self, _value):
        if not datetime.datetime.strptime(_value, '%d.%m.%Y'):
            raise ValueError("must be date %d.%m.%Y {}".format(_value))
        self._value = _value


class BirthDayField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=str):
        super(BirthDayField, self).__init__(name, required, nullable, type_check)

    @property
    def value(self):
        super(BirthDayField, self).value

    @value.setter
    def value(self, _value):
        if (datetime.datetime.now() -
           datetime.datetime.strptime(_value, '%d.%m.%Y')).days > 365 * 70:
            raise ValueError("must be less 70 years old".format(_value))
        self._value = _value


class GenderField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=str):
        super(GenderField, self).__init__(name, required, nullable, type_check)

    @property
    def value(self):
        super(GenderField, self).value

    @value.setter
    def value(self, _value):
        if _value and _value not in (UNKNOWN, MALE, FEMALE):
            raise ValueError("must be 0 (UNKNOWN), \
                              1 (MALE), \
                              2 (FEMALE) {}".format(_value))
        self._value = _value


class ClientIDsField(BaseField):
    def __init__(self, name=None, required=False,
                 nullable=True, type_check=str):
        super(ClientIDsField, self).__init__(name, required, nullable, type_check)

    @property
    def value(self):
        super(ClientIDsField, self).value

    @value.setter
    def value(self, _value):
        if not isinstance(_value, list) or \
           any(not isinstance(x, int) for x in _value):
            raise ValueError("must be list of int".format(_value))
        if len(_value) == 0:
            raise ValueError("empty list".format(_value))
        self._value = _value


class BaseRequest(object):
    def __init__(self, request):
        self.request = request


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, request):
        super(ClientsInterestsRequest, self).__init__(request)
        self.request = request
        self.client_ids.value = self.request["body"]["arguments"]["client_ids"]
        self.date.value = self.request["body"]["arguments"]["date"]

    @property
    def get_interests(self):
        interests = {"score": scoring.get_interests(
                        store=None,
                        cid=self.client_ids.value,
                        )}
        return interests


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, request):
        super(OnlineScoreRequest, self).__init__(request)
        self.request = request
        self.first_name.value = self.request["body"]["arguments"]["first_name"]
        self.last_name.value = self.request["body"]["arguments"]["last_name"]
        self.email.value = self.request["body"]["arguments"]["email"]
        self.birthday.value = self.request["body"]["arguments"]["birthday"]
        self.gender.value = self.request["body"]["arguments"]["gender"]
        self.phone.value = self.request["body"]["arguments"]["phone"]

    # @staticmethod
    @property
    def get_score(self):
        score = {"score": scoring.get_score(
                        store=None,
                        phone=self.phone.value,
                        email=self.email.value,
                        birthday=self.birthday.value,
                        gender=self.gender.value,
                        first_name=self.first_name.value,
                        last_name=self.last_name.value
                        )}
        if (self.email.value and self.phone.value) or \
           (self.first_name.value and self.last_name.value) or \
           (self.gender.value and self.birthday.value):
            return score


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request):
        super(MethodRequest, self).__init__(request)
        self.request = request
        self.account.value = request["body"]["account"]
        self.login.value = request["body"]["login"]
        self.token.value = request["body"]["token"]
        self.arguments.value = request["body"]["arguments"]
        self.method.value = request["body"]["method"]

    @property
    def response(self):
        if self.method.value == "online_score":
            if self.login.value == ADMIN_LOGIN:
                return {"score": 42}, 200
            else:
                score = OnlineScoreRequest(self.request)
            return score.get_score, 200
        if self.method.value == "clients_interests":
            interests = ClientsInterestsRequest(self.request)
            return interests.get_interests, 200

    # @property
    # def is_admin(self):
    #     return self.login == ADMIN_LOGIN


def check_auth(request):
    # if request.is_admin:
    login = MethodRequest.parse(request, "login")
    account = MethodRequest.parse(request, "account")
    token = MethodRequest.parse(request, "token")
    if login == ADMIN_LOGIN:
        digest = hashlib.sha512(
                 datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT) \
                 .hexdigest()
    else:
        # digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
        digest = hashlib.sha512(account + login + SALT).hexdigest()
    # if digest == request.token:
    if digest == token:
        return True
    return False


def method_handler(request, ctx, store):
    answer = MethodRequest(request)
    response, code = answer.response
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path,
                                        data_string,
                                        context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request,
                                                        "headers": self.headers
                                                        }, context, self.store)
                except Exception:
                    logging.exception("Unexpected error: %s" % Exception)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log,
                        level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
