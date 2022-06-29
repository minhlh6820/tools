import os
import json
import random
import string
from packaging import version
import subprocess
# from config.api import SecurityboxAPI
from urllib.parse import urlparse

options = {
    "plugin_id": "7214"
}


def wordpress(new_task, proxy_config, content):
    # self.get_input()
    full_link = new_task["url_info"][0]["url"]
    if get_tech(new_task) is True:
        current_path = os.path.dirname(os.path.realpath(__file__))
        output_file = os.path.join(current_path, "{}.json".format(
            ''.join(random.choice(string.ascii_uppercase) for _ in range(5))))
        wordpress_path = os.path.join(current_path, "directory/wordpresses.json")
        theme_path = os.path.join(current_path, "directory/themes.json")
        plugin_path = os.path.join(current_path, "directory/plugins.json")
        o = urlparse(full_link)
        url = '{uri.scheme}://{uri.netloc}'.format(uri=o)
        # Path(os.path.join(current_path,"../tools/wordpress_lib")).mkdir(parents=True, exist_ok=True)
        if proxy_config:
            (k, proxy), = proxy_config.items()
            command = "wpscan --update --url {} -f json -o {} --proxy {} --random-user-agent".format(url, output_file, proxy)
            print(command)
        else:
            command = "wpscan --update --url {} -f json -o {} --random-user-agent".format(url, output_file)
            print(command)
        process = subprocess.Popen(command, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None,
                                   close_fds=True)
        try:
            stdout, stderr = process.communicate(timeout=2700)
            with open(output_file, "r+") as f:
                input_data = json.load(f)
                wp_version = input_data["version"]["number"]
                main_theme = input_data["main_theme"]["slug"]
                main_theme_version = input_data["main_theme"]["version"]["number"]
                plugins = input_data["plugins"]
            wp_vuln_id = get_wp_vuln(wp_version, wordpress_path)
            theme_vuln_id = get_theme_vuln(main_theme, main_theme_version, theme_path)
            plugin_vuln_id = get_plugin_vuln(plugins, plugin_path)
            list_id = wp_vuln_id + theme_vuln_id + plugin_vuln_id
            if list_id:
                for _id in list_id:
                    get_result(new_task, _id)
        except (Exception, subprocess.TimeoutExpired) as err:
            print(err)
        if os.path.exists(output_file):
            os.remove(output_file)


def get_tech(new_task):
    flag = False
    if new_task["url_info"][0]["is_first_url"] is True and new_task["technologies"]:
        for value in new_task["technologies"]:
            if str(value["app"]).lower() == "wordpress":
                flag = True
    return flag


def get_wp_vuln(wp_version, path):
    list_id = []
    with open(path, "r+") as f:
        input_data = json.load(f)
        if wp_version in input_data.keys():
            vuln = input_data[wp_version]["vulnerabilities"]
            if vuln:
                for x in vuln:
                    list_id.append(x["id"])
    return list_id


def get_theme_vuln(theme, ver, path):
    list_id = []
    with open(path, "r+") as f:
        input_data = json.load(f)
        if theme in input_data.keys():
            vuln = input_data[theme]["vulnerabilities"]
            if vuln:
                for x in vuln:
                    if not x["fixed_in"] or version.parse(ver) < version.parse(x["fixed_in"]):
                        list_id.append(x["id"])
    return list_id


def get_plugin_vuln(plugins, path):
    list_id = []
    with open(path, "r+") as f:
        input_data = json.load(f)
        for plugin in plugins:
            if plugin in input_data.keys():
                vuln = input_data[plugin]["vulnerabilities"]
                ver = plugins[plugin]["version"]["number"]
                if vuln:
                    for x in vuln:
                        if not x["fixed_in"] or version.parse(ver) < version.parse(x["fixed_in"]):
                            list_id.append(x["id"])
    return list_id


def get_result(new_task, _id):
    # web_api = SecurityboxAPI()
    plugin_id = options.get("plugin_id")
    data_host_vuln = {
        "scan": new_task["id"],
        "security_risk": _id,
        "nvt": plugin_id,
        "object": str(new_task["url_info"][0]["url"]),
        "port": "",
        "family": "wordpress",
        "affects": str(new_task["url_info"][0]["url"]),
        "param": "",
        "attack_detail": "",
        "attack_detail_en": "",
        "request": "",
        "output": "",
        "output_en": ""
    }
    # post detail vuln to service
    # web_api.post_core_result(data_host_vuln)
    print("\n")
    print(data_host_vuln)

if __name__ == '__main__':
    new_task = {
        "id": 1583,
        "target": 319,
        "task": 495,
        "module": 5,
        "scan_objects": [
            "http://leettime.net/tasks/basic_ch4.php"
        ],
        "configuration": {
            "speed": 4,
            "scan_config": "standard",
            "scan_custom_configs": None,
            "exclude_url": [
                ""
            ],
            "crawler_manual_file": None,
            "custom_headers": {},
            "custom_cookies": [],
            "user_agent": None,
            "using_vpn": False,
            "using_proxy": False
        },
        "credentials": [],
        "technologies": [
            {
                "technology": "Web Servers",
                "app": "WordPress",
                "version": "4.7.2"
            },
            {
                "technology": "Programming Languages",
                "app": "PHP",
                "version": "5.6.40"
            }
        ],
        "url_info": [
            {
                "url": "http://aapgroup.com.kh/",
                "name": "",
                "method": "POST",
                "params": {
                    # "ext": ["com_content"],
                    # "query": ["1"],
                    # "order": ["relevance"]
                },
                "request_header": {
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                    "user-agent": "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.124"
                },
                "request_body": "",
                "content_key": "495-1497:883922b67bc970cab5fb8d9c09051582",
                "response_header": {
                    "date": "Fri, 19 Jul 2019 08:48:01 GMT",
                    "vary": "Accept-Encoding,User-Agent",
                    "server": "Apache",
                    "connection": "Keep-Alive",
                    "keep-alive": "timeout=5",
                    "content-type": "text/html; charset=UTF-8",
                    "x-powered-by": "PHP/5.6.40",
                    "content-length": "1738",
                    "content-encoding": "gzip"
                },
                "is_login": False,
                "is_first_url": True,
                "http_version": 1,
                "status": 200,
                "security_level": "safe"
            }
        ],
        "status": "requested",
        "progress": 0,
        "additional_info": [],
        "agent_uuid": "d869d1d5-01ef-4a9d-86ea-916f0adab2a1"
    }

    # proxy_config = {"http": "http://user:pass@ip_proxy:port"}
    proxy_config = {}

    content = {
        "url": "http://drei-schneeballen.de/wp-content/plugins/nextgen-gallery/changelog.txt",
        "request": {
            "method": "GET",
            "post_data": None,
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.124",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                "Accept-Encoding": "gzip, deflate",
                "content-type": "application/x-www-form-urlencoded"
            },
            "resourceType": "document",
            "click": []
        },
        "response": {
            "status": 401,
            "content": '<a href="/docs/manager-howto.html">Manager App HOW-TO</a>',
            "headers": {
                "server": "nginx/1.4.1",
                "date": "Mon, 09 Feb 1970 02:53:50 GMT",
                "content-type": "text/html",
                "transfer-encoding": "chunked",
                "connection": "keep-alive",
                "x-powered-by": "PHP/5.3.10-1~lucid+2uwsgi2",
                "content-encoding": "gzip"
            },
            "resourceType": "document"
        }
    }

    print("Run")
    wordpress(new_task, proxy_config, content)
