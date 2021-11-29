#!/usr/bin/env python3
import argparse
import base64
import requests
import socket
import random
import time
import uuid
import string
import hashlib
import json
import traceback
import logging
import sys
import contextlib

from http.client import HTTPConnection
from requests.exceptions import Timeout
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import sploit

from typing import Optional, Callable

### Common checker stuffs ###

class WithExitCode(Exception):
    code: int

    def __init__(self, msg_opt: Optional[str] = None) -> None:
        msg = ""
        name = self.__class__.__name__
        if msg_opt is not None:
            msg = name + ": " + msg_opt
        else:
            msg = name
        super().__init__(msg)
class Corrupt(WithExitCode):
    code = 102
class Mumble(WithExitCode):
    code = 103
class Down(WithExitCode):
    code = 104
class CheckerError(WithExitCode):
    code = 110

class Color:
    value: bytes

    @classmethod
    def print(cls, msg: str) -> None:
        sys.stdout.buffer.write(b"\x1b[01;" + cls.value + b"m")
        sys.stdout.buffer.flush()
        print(msg)
        sys.stdout.buffer.write(b"\x1b[m")
        sys.stdout.buffer.flush()
class Red(Color):
    value = b"31"
class Green(Color):
    value = b"32"

### Logic starts here ###

HTTPConnection.debuglevel = 0 # type: ignore
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger("checker")
# log.propagate = True

TB_API_PORT = 6001
TB_AUTH_HEADER = 'XTBAuth'
SELENIUM_ADDRESS1 = 'http://5.45.248.209:31337/users'
SELENIUM_ADDRESS2 = 'http://5.45.248.216:31337/users'
SELENIUM_ADDRESS3 = 'http://5.45.248.215:31337/users'


def get_sha256(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


flag_alphabet = string.digits + string.ascii_uppercase


def generate_some_flag():
    # [0-9A-Z]{31}=
    flag = []
    for i in range(31):
        flag.append(random.choice(flag_alphabet))
    flag.append('=')

    return ''.join(flag)


def get_session_with_retry(
        retries=3,
        backoff_factor=0.3,
        status_forcelist=(400, 404, 500, 502),
        session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)

    return session


def get_random_selenium():
    return random.choice([SELENIUM_ADDRESS1, SELENIUM_ADDRESS2, SELENIUM_ADDRESS3])


def put(hostname: str, flag: str) -> str:
    try:
        nickname = 'user-' + str(uuid.uuid4())
        password = str(uuid.uuid4())
        password_sha256 = get_sha256(password)

        log.debug(f'creating user {nickname} with password {password} ({password_sha256})')

        response = get_session_with_retry().post(
            f"http://{hostname}:{TB_API_PORT}/api/users",
            json={
                "nickname": nickname,
                "password_sha256": password_sha256,
                "payment_info": flag
            },
        )

        log.debug(f'response: \ncode: {response.status_code}\nheaders:{response.headers}\ntext:{response.text}')

        if response.status_code != 200:
            log.error(f'unexpected code - {response.status_code}')
            raise Mumble("Wrong server response")

        response_json = response.json()
        auth_token = response_json['auth_token']
        log.debug(f'user created with auth_token {response.json()}')

        if response.headers[TB_AUTH_HEADER] != auth_token:
            raise Mumble("Wrong server response")

        try:
            log.debug(f'sending ({auth_token} {hostname}) into selenium..')
            response = get_session_with_retry().post(
                get_random_selenium(), json={
                    'auth_token': auth_token,
                    'host': hostname
                }
            )
            log.debug(response.text)

            if response.status_code != 201:
                raise ValueError('status code is not 200')
        except Exception as e:
            log.error(f'cannot send user info into selenuim')
            log.error(e)

        return auth_token
    except Exception as e:
        traceback.print_exc()
        raise Down("can't create user")


def get(hostname: str, flag_id: str, flag: str) -> None:
    try:
        response = get_session_with_retry().get(
            f"http://{hostname}:{TB_API_PORT}/api/users",
            headers={TB_AUTH_HEADER: flag_id},
            timeout=3
        )

        log.debug(f'response: \ncode: {response.status_code}\nheaders:{response.headers}\ntext:{response.text}')

        if response.json()['payment_info'] == flag:
            return
        else:
            raise Corrupt('wrong flag')
    except Timeout as e:
        traceback.print_exc()
        raise Down("service not responding")
    except Exception as e:
        traceback.print_exc()
        raise Corrupt("service can't give a flag")


def check(hostname: str) -> None:
    try:
        nickname = 'user-' + str(uuid.uuid4())
        password = str(uuid.uuid4())
        password_sha256 = get_sha256(password)
        flag = generate_some_flag()

        log.info(f">>>>> {nickname} with password {password} and flag {flag}")

        session = get_session_with_retry()

        log.debug(f"Connecting to {hostname}")
        auth_token = check_creation(hostname, flag, nickname, password_sha256, session)

        check_get_user(auth_token, hostname, session, flag, nickname)
        check_auth(hostname, nickname, password_sha256, session, auth_token)
        latest_posts_ids = check_latest(hostname, session, auth_token)
        check_likes_on_posts(hostname, session, auth_token, latest_posts_ids)
        post_id = check_make_some_post(hostname, session, auth_token)

        log.info(f"<<<<< {nickname}")

        return
    except Timeout as e:
        traceback.print_exc()
        raise Down("service not responding")
    except Exception as e:
        traceback.print_exc()
        raise Corrupt("service can't give a flag")


def check_make_some_post(hostname: str, session, auth_token) -> int:
    track = json.dumps({
        'notes': ''.join(
            [random.choice(["C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"]) for _ in range(20)]),
        'waveform': random.choice(["sine", "square", "sawtooth", "triangle"])
    })
    track = base64.b64encode(track.encode('utf-8')).decode('utf-8')
    title = ''.join([random.choice(string.ascii_letters) for _ in range(15)])
    description = ''.join([random.choice(string.ascii_letters) for _ in range(15)])
    r = session.post(
        f'http://{hostname}:{TB_API_PORT}/api/posts',
        cookies={
            TB_AUTH_HEADER: auth_token
        },
        json={
            'track': track,
            'title': title,
            'description': description
        }
    )
    log.info(r.text)

    if r.status_code != 200:
        raise Mumble("Wrong server response")

    post_id = r.json().get('post_id')

    r = session.get(
        f'http://{hostname}:{TB_API_PORT}/api/posts/{post_id}',
        headers={TB_AUTH_HEADER: auth_token}
    )
    log.info(r.text)

    if r.status_code != 200 or r.json().get('track') != track or r.json().get('title') != title or r.json().get(
            'description') != description:
        raise Mumble("Wrong server response")

    return post_id


def check_auth(hostname: str, nickname, password_sha256, session, auth_token):
    r = session.put(
        f"http://{hostname}:{TB_API_PORT}/api/users/auth_token",
        json={
            "nickname": nickname,
            "password_sha256": password_sha256,
        }
    )
    log.info(r.text)

    if r.status_code != 200 or r.headers.get(TB_AUTH_HEADER) != auth_token or r.json().get('auth_token') != auth_token:
        raise Mumble("Wrong server response")

    return None


def check_get_user(auth_token, hostname: str, session, flag, nickname):
    r = session.get(
        f"http://{hostname}:{TB_API_PORT}/api/users",
        cookies={
            TB_AUTH_HEADER: auth_token
        },
    )
    log.info(r.text)
    j = r.json()

    if r.status_code != 200 or j.get('payment_info') != flag or j.get('nickname') != nickname or j.get('posts') != []:
        raise Mumble("Wrong server response")

    return None


def check_creation(hostname: str, flag, nickname, password_sha256, session):
    r = session.post(
        f"http://{hostname}:{TB_API_PORT}/api/users",
        json={
            "nickname": nickname,
            "password_sha256": password_sha256,
            "payment_info": flag
        },
    )
    log.info(r.text)
    auth_token = r.headers.get(TB_AUTH_HEADER)

    if r.status_code != 200 or auth_token is None:
        raise Mumble("Wrong server response")

    return auth_token


def check_latest(hostname: str, session, auth_token) -> list:
    r = session.get(
        f"http://{hostname}:{TB_API_PORT}/api/posts/latest?limit=100",
        cookies={
            TB_AUTH_HEADER: auth_token
        },
    )
    log.info(r.text)

    posts = r.json().get('posts')
    if r.status_code != 200 or posts is None or len(posts) > 100:
        raise Mumble("Wrong server response")

    if len(posts) == 0:
        return []

    return [random.choice(posts) for _ in range(5)]


def check_likes_on_posts(hostname: str, session, auth_token, latest_posts_ids):
    for post in latest_posts_ids:
        r = session.get(
            f"http://{hostname}:{TB_API_PORT}/api/posts/{post}",
            headers={TB_AUTH_HEADER: auth_token}
        )
        log.info(r.text)

        j = r.json()

        if r.status_code != 200:
            raise Mumble("Wrong server response")

        for k in ['author', 'comments', 'description', 'likes_amount', 'publishing_date', 'title', 'track']:
            if j.get(k) is None:
                raise Mumble("Wrong server response")

        current_likes = int(j.get('likes_amount'))

        r = session.put(
            f"http://{hostname}:{TB_API_PORT}/api/posts/{post}",
            cookies={
                TB_AUTH_HEADER: auth_token
            },
        )
        log.info(r.text)

        if r.status_code != 200:
            raise Mumble("Wrong server response")

        r = session.get(
            f"http://{hostname}:{TB_API_PORT}/api/posts/{post}",
            headers={TB_AUTH_HEADER: auth_token}
        )
        log.info(r.text)

        j = r.json()

        if r.status_code != 200:
            raise Mumble("Wrong server response")

        for k in ['author', 'comments', 'description', 'likes_amount', 'publishing_date', 'title', 'track']:
            if j.get(k) is None:
                raise Mumble("Wrong server response")

        new_likes = int(j.get('likes_amount'))

        if new_likes != 100500 and new_likes != current_likes + 1 and new_likes != current_likes + 2 and new_likes != current_likes + 3:
            raise Mumble("Wrong server response")

    return None


def command_run(hostname: str, selenium: bool) -> None:
    for _ in range(5):
        check(hostname)
        Green.print("check")
    try:
        sploit.attack(hostname, TB_API_PORT, selenium)
        Red.print("attack")
    except sploit.AttackError:
        Green.print("attack")

def main(args: argparse.Namespace, usage: Callable[[], None]) -> int:
    try:
        if args.command == "get":
            get(args.host, args.flag_id, args.flag)
        elif args.command == "put":
            flag_id = put(args.host, args.flag)
            print("flag_id: " + flag_id)
        elif args.command == "check":
            check(args.host)
        elif args.command == "attack":
            r = sploit.attack(args.host, TB_API_PORT, args.selenium)
            print(r)
        elif args.command == "run":
            command_run(args.host, args.selenium)
        else:
            print(f"Incorrect command: {args.command}")
            usage()
            return CheckerError.code
        # if not thrown, everything is ok
        return 101
    except IndexError:
        usage()
        return CheckerError.code
    except WithExitCode as e:
        Red.print(str(e))
        return e.code
    except sploit.AttackError as e:
        Red.print("AttackError: " + str(e))
        return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Checker for trackbattle")
    parser.add_argument("command", metavar="COMMAND", type=str, help="run|check|put|get|attack")
    parser.add_argument("host", metavar="HOST", type=str, help="address of host (you probably want 'localhost')")
    parser.add_argument("flag", metavar="FLAG", type=str, help="flag to put or to get. Only required for those commands", nargs="?", default="")
    parser.add_argument("flag_id", metavar="FLAG_ID", type=str, help="Noone knows what this is, but it's used by upstream libraries", nargs="?", default="")
    parser.add_argument("--selenium", dest="selenium", action="store_true", help="use selenium in docker for automatic XSS checking (works like garbage)")
    parser.add_argument("--loglevel", dest="loglevel", type=int, default=logging.WARNING, help="log level from 0 (log everything) to 50 (only critical logs)")
    parser.add_argument("--debug-http", dest="debug_http", action="store_true", help="print debug messages for all http requests")
    args = parser.parse_args()

    log.setLevel(args.loglevel)
    if args.debug_http:
        HTTPConnection.debuglevel = 1 # type: ignore

    sys.exit(main(args, parser.print_help))
