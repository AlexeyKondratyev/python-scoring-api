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
    def __init__(self, required=False, nullable=False):
        self._required = required
        self._nullable = nullable
        self.value = None

    def field_validation(self, value):
        if not hasattr(self, "value") and self._required:
            raise ValueError("field is required")
        if value is None and not self._nullable:
            raise  ValueError("field can't be nullable")
        if type(value) not in self._type:
            raise ValueError("wrong field type")

    def is_valid(self, value):
        self.field_validation(value)
        return value
        
class CharField(BaseField):
    _type = [str, unicode]


class ArgumentsField(BaseField):
    _type = [dict]

class EmailField(CharField):

    def is_valid(self, value):
        self.field_validation(value)
        if not value:
            return value
        if "@" not in value:
            raise ValueError("e-mail address must be str or unicode with '@'")
        return value


class PhoneField(BaseField):
    _type = [str, unicode, int]

    def is_valid(self, value):
        self.field_validation(value)
        if not value:
            return value
        pattern = "^7[0-9]{10}$"
        if re.match(pattern, str(value)) is None:
            raise ValueError("phone must be str, unicode or int like '7<10 numbers>'")
        return value

class DateField(BaseField):
    _type = [str, unicode]

    def is_valid(self, value):
        self.field_validation(value)
        if not value:
            return value
        try:
            value = datetime.datetime.strptime(str(value), "%d.%m.%Y").date()
        except TypeError:
            raise ValueError("Must be %d.%m.%Y format")
        except ValueError:
            raise ValueError("Must be %d.%m.%Y format")
        return value

class BirthDayField(DateField):
    def is_valid(self, value):
        self.field_validation(value)
        value = super(BirthDayField, self).field_validation(value)
        if not value:
            return value
        now_date = datetime.datetime.now().date()
        print(now_date.year)
        print(value)
        if now_date.year - value.year >= 70:
            raise ValueError("must be less than 70 years")
        return value

class GenderField(BaseField):
    _type = [int]

    def __init__(self, required=False, nullable=True):
        super(GenderField, self).__init__(required, True)

    def is_valid(self, value):
        self.field_validation(value)
        if value is None:
            return value
        if value not in GENDERS:
            raise ValueError("Gender must 0, 1 or 2")
        return value

class ClientIDsField(BaseField):
    _type = [list]

    def is_valid(self, value):
        self.field_validation(value)
        if not value:
            return value
        for v in value:
            if type(v) is not int:
                raise ValueError("id must be int")
        return value

class MetaMethods(type):
    def __new__(cls, name, bases, attrs):
        new_class = super(MetaMethods, cls).__new__(cls, name, bases, attrs)
        new_class.fields = {}
        for field, class_field in attrs.items():
            if isinstance(class_field, BaseField):
                new_class.fields[field] = class_field
        return new_class

class Methods(object):
    def __init__(self):
        self.has = {}

    def load_n_validate(self, **kwargs):
        errors = []
        for field, class_field in self.fields.items():
            if field in kwargs:
                value = kwargs.get(field)
            else:
                value = None
            try:
                value = class_field.is_valid(value)
                setattr(self, field, value)
                if value is not None:
                    self.has[field] = value
            except ValueError as ve:
                errors.append("Validation error ({}) on field: {}".format(ve, field))
        if errors:
            raise ValueError(", ".join(errors))
        self.is_valid()

    def is_valid(self):
        pass

class ClientsInterestsRequest(Methods):
    __metaclass__ = MetaMethods

    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

class OnlineScoreRequest(Methods):
    __metaclass__ = MetaMethods

    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def is_valid(self):
        if (self.first_name is None or self.last_name is None)\
                and (self.phone is None or self.email is None)\
                and (self.birthday is None or self.gender is None):

            raise ValueError("Fields pairs is required (for score solving)")

class MethodRequest(Methods):
    __metaclass__ = MetaMethods

    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    # return False
    return True

def method_handler(request, ctx, store):
    methods = {'online_score': online_score_handler,
                'clients_interests': clients_interests_handler}

    try:
        method_request = MethodRequest()
        method_request.load_n_validate(**request["body"])
        if not check_auth(method_request):
            return "", FORBIDDEN
        response, code = methods[method_request.method](store, method_request, ctx)
    except ValueError as e:
        logging.info("Format json failed. request: %s" % request)
        return str(e), INVALID_REQUEST
    else:
        return response, code

def online_score_handler(store, request, ctx):

    score_request = OnlineScoreRequest()
    score_request.load_n_validate(**request.arguments)
    if request.is_admin:
        score = 42
    else:
        score = scoring.get_score(store=store, phone=score_request.phone, email=score_request.email,
                                  birthday=score_request.birthday, gender=score_request.gender,
                                  first_name=score_request.first_name, last_name=score_request.last_name)

    ctx["has"] = list(score_request.has.keys())

    return {"score": score}, OK


def clients_interests_handler(store, request, ctx):
    client_request = ClientsInterestsRequest()
    client_request.load_n_validate(**request.arguments)
    interests = {cid: scoring.get_interests(store=store, cid=cid) for cid in client_request.client_ids}

    ctx["nclients"] = len(interests)
    ctx["has"] = client_request.has

    return interests, OK

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
