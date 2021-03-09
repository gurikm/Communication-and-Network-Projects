"""
Name:Gurik Manshahia
Student Id:V00863509
Date:2021-01-27
"""
import socket
import sys
import ssl

#Redirection function used when
#switching between ports
def redirection(result):
    new_hoster=""
    Location_start = result.find("Location:")
    counter = Location_start + 10
    new_host = ""
    while(result[counter] != '\r'):
        new_host = new_host+result[counter]
        counter = counter + 1
    new_hoster = new_host.split('/')
    return new_hoster
                
#Port 80 returns the https versions 
#along with the cookies and other required information
def port80(ip_address, support_http2,https,host):
    response = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        address = (ip_address, 80)  # HTTP
        sock.connect(address)  # Connect to HTTP address
        count = sock.sendall(bytes('GET / HTTP/1.1\r\nHost: ' + host + '\r\nConnection: keep-alive\r\n\r\n','utf8'))  # GET request
        if count == 0:  # If failed to send
            print('Failed to check HTTP')
        receive = sock.recv(1024)  # Receiving response
        while len(receive):
            response = response + bytes.decode(receive)
            receive = sock.recv(1024)
    except Exception as e:
        sock.close()
    count = 0

    while True:
        index = response.find('\n')
        if index == -1:
            find_word = response
        else:
            find_word = response[:index]
        if len(find_word) == 0 or find_word[0] == '\r':
            break
        if error_handling(find_word[9:12],80,support_http2,https,response) == 'break':
            break
        if find_word.find('HTTP') == 0: 
            if https == True:
                print('1. Support of HTTPS: yes')
            else: 
                print('1. Support of HTTPS: no')
            if find_word[:8] == 'HTTP/1.1':
                print('2. Supports http1.1: yes')
            else:
                print('2. Supports http1.1: no')
            if support_http2 == True:
                print('3. Supports http2: yes')
            else:
                print('3. Supports http2: no')
        
        if find_word.find('Set-Cookie') == 0: 
            cookie = find_word[12:]
            index2 = cookie.find('=')
            key = cookie[:index2]
            cookie = cookie[index2 + 1:]
            index3 = cookie.find(';') 
            expire = ''
            domain = ''
            if index3 != -1:
                index4 = cookie.lower().find('domain=')  # Get domain
                dom = cookie[index4:]
                temp = dom.lower().find('domain=')
                finder = dom.find(';')
                if index4 != -1:
                    domain = dom[temp+7:finder]
                index5 = cookie.find('expires=') #get expire
                exp = cookie[index5:]
                temp1 = exp.find('expires=')
                finder1 = exp.find(';')
                if index5 != -1:
                    expire = exp[temp1+8:finder1+1]
            if count == 0: 
                print('4. List of Cookies:  ')
                count = count + 1
            print('Cookie name: ', end= ""+ key)
            if expire != '':
                print(' Expire: ', end=""+expire)
            if domain != '':
                print(' Domain name: ', end="" + domain)
            print("")
        if index == -1:
            break
        response = response[index + 1:]  

#Port 443 returns the https versions 
#along with the cookies and other required information
def port443(ip_address, support_http2,https,host):
    response = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = ssl.wrap_socket(sock)  # Wrap with SSL
        sock.settimeout(1)
        address = (ip_address, 443)  # HTTPS
        sock.connect(address)
        count = sock.sendall(bytes('GET / HTTP/1.1\r\nHost: ' + host + '\r\nConnection: keep-alive\r\n\r\n', 'utf8'))  # GET request
        receive = sock.recv(1024)  # Receiving response
        while len(receive):
            response = response + bytes.decode(receive)
            receive = sock.recv(1024)
    except Exception as e:
        sock.close()
    count = 0
    while True:
        index = response.find('\n')
        if index == -1:
            find_word = response
        else:
            find_word = response[:index]
        if len(find_word) == 0 or find_word[0] == '\r':
            break
        if error_handling(find_word[9:12],443,support_http2,https,response) == 'break':
            break
        if find_word.find('HTTP') == 0: 
            if https == True:
                print('1. Support of HTTPS: yes')
            else: 
                print('1. Support of HTTPS: no')
            if find_word[:8] == 'HTTP/1.1':
                print('2. Supports http1.1: yes')
            else:
                print('2. Supports http1.1: no')
            if support_http2 == True:
                print('3. Supports http2: yes')
            else:
                print('3. Supports http2: no')
        
           
        if find_word.find('Set-Cookie') == 0: 
            cookie = find_word[12:]
            index2 = cookie.find('=')
            key = cookie[:index2]
            cookie = cookie[index2 + 1:]
            index3 = cookie.find(';') 
            expire = ''
            domain = ''
            if index3 != -1:
                index4 = cookie.lower().find('domain=')  # Get domain
                dom = cookie[index4:]
                temp = dom.lower().find('domain=')
                finder = dom.find(';')
                if index4 != -1:
                    domain = dom[temp+7:finder]
                index5 = cookie.find('expires=') #get expire
                exp = cookie[index5:]
                temp1 = exp.find('expires=')
                finder1 = exp.find(';')
                if index5 != -1:
                    expire = exp[temp1+8:finder1+1]
            if count == 0: 
                print('4. List of Cookies:  ')
                count = count + 1
            print('Cookie name: ', end= ""+ key)
            if expire != '':
                print(' Expire: ', end=""+expire)
            if domain != '':
                print(' Domain name: ', end="" + domain)
            print("")
        if index == -1:
            break
        response = response[index + 1:]  
        
            

#Returns error code if any and the information
#on the error Also casue redirection if
#error 301 or 302 occur.
def error_handling(error_check, port,support_http2,https,response): #done

    if error_check == '505':
        print('Status code: ' + error_check + ' - HTTP version not supported\n')
    if error_check == '404':
        print('Status code: ' + error_check + ' - Requested document does not exist on this server\n')
    if error_check == '200':
         print('Status code: ' + error_check + ' - request succeeded information returned\n')
    if port == 443:
        if error_check == '302':
            print('Status code: ' + error_check + ' - Found')
            print('Redirecting to new location (over port 443)\n')
            new_host = redirection(response)
            new_ip = socket.gethostbyname(new_host[2])
            port80(new_ip, support_http2,https,new_host[2])  # port443 to new location
            return 'break'
        if error_check == '301':
            print('Status code: ' + error_check + ' - Moved Permantly')
            print('Redirecting to new location (over port 443)\n')
            new_host = redirection(response)
            new_ip = socket.gethostbyname(new_host[2])
            port80(new_ip, support_http2,https,new_host[2])  # port443 to new location
            return 'break'
    if port == 80:
        if error_check == '302':
            print('Status code: ' + error_check + ' - Found')
            print('Redirecting to new location (over port 80)\n')
            new_host = redirection(response)
            new_ip = socket.gethostbyname(new_host[2])
            port443(new_ip, support_http2,https,new_host[2])  # port80 to new location
            return 'break'        
        if error_check == '301':
            print('Status code: ' + error_check + ' - Moved permantly')
            print('Redirecting to new location (over port 80)\n')
            new_host = redirection(response)
            new_ip = socket.gethostbyname(new_host[2])
            port443(new_ip, support_http2,https,new_host[2])  # port80 to new location
            return 'break'

#-------------------------------------------Main Function----------------------------------------------------
def main(): 
    if len(sys.argv) != 2:
        print("Error: invalid URL")
        return
    host = sys.argv[1]
    print('Website: ' + sys.argv[1])
    ip_address = socket.gethostbyname(socket.getfqdn(sys.argv[1]))
    print('IP: ' + ip_address)
    address = (ip_address, 443)
    try:
        sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))  # Wrap the socket
        sock.settimeout(1)
        if sock.connect(address) != socket.error:  # Check for HTTPS support
            print('connecting to port 443')
            https = True
            sock.close()
    except Exception as e:
        print('connecting to port 80')
        https = False
    try:
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        context.set_alpn_protocols(['h2','http/1.1'])
   
        connection = socket.create_connection((sys.argv[1], 443)) #establish tcp connection

        secureSocket = context.wrap_socket(connection, server_hostname=sys.argv[1])
        negotiated_protocol = secureSocket.selected_alpn_protocol()
        if negotiated_protocol is None:
            negotiated_protocol = secureSocket.selected_npn_protocol()
        if negotiated_protocol == "h2":
           support_http2 = True
        else:
            support_http2 = False
    except Exception as e:
        support_http2 = False

    #if https is true connects to port 443 else port 80
    if https:
        port443(ip_address, support_http2,https,host)
    else:
        port80(ip_address, support_http2,https,host)

#-------------------------------------------Main Function----------------------------------------------------


if __name__ == '__main__':
    main()
    print('\n')