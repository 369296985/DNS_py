import sys
import socket
import _thread
import time
import re
import os
import random
'''
初始程序界面
'''
print("DNSRELAY     Version 1.0     Build: 2018-4-5")
print("Author: 刘忠新、杨双、胡惠中")
print("Usage: dnsrelay.py [-d | -dd] [dns-server-ipaddr] [filename] \n")

'''
全局变量定义

'''

sequence=0  #接收到的请求报文序号（注意是来自客户端的请求报文）

profile='dnsrelay.txt'  #默认的配置文件名，可修改
DNS_IP='10.3.9.4'   #默认的外部DNS服务器IP

PORT=53    #从本机53号端口获取字节流

debug_level=0   #调试级别，默认情况下为0，-d为1，-dd为2

data={}    #这是一个字典，用于存储从配置文件中读取的 域名-IP对照， 键 为域名，值 为IP（域名和IP都是字符串）

#msg=bytes(0)   用于存储从本机53号端口接收到的字节流
#client_IP=' '  字节流来源客户端IP
#client_port=0 字节流来源客户端端口号

#head_ID=b''   报头ID
#domain_name=''  存储解析的域名
#TYPE=1   需要解析的IP类型，如果TYPE==28，即为IPV6，如果TYPE==1，即为IPV4，本地只能查找TYPE==1的地址

time_delay=2   #默认的延迟时间2秒，超过这个时间就认为超时了，需要进行超时处理 

ID={}   #这是一个字典，当从data中查不到对应的IP时需要向其他DNS寻求帮助，此时，需要将从客户端接收到的请求报文ID转化一下再发出。键为转化后的ID，值为（client_IP,client_port,client_ID）
TIME=[]  #这是一个列表，存储的是向另一个DNS发送的报文的时间，格式为（ID，发送时间），用于超时处理。
lock=0  #这是一把互斥锁，用于对TIME进行操作，只有当lock=0的时候才可以对TIME进程操作，操作时需将lock设为1，操作完需将lock设为0

s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)  #socket对象
s.bind(('',PORT))   #绑定端口53号
print("Bind port 53...OK")
#socket.setdefaulttimeout(20)

'''
                 init()   命令解析及初始化--刘忠新
    1.根据dos中的命令初始化参数：DNS_IP , profile , debug_level 
    2.检查本地配置文件是否存在，如果存在，将文件中的数据存到字典data里
    3.检查外部DNS服务器是否可用

    初始化成功返回1，失败返回0
'''
def init():
    global debug_level,DNS_IP,profile,data
    
    #解析命令行中的命令
    pattern1=re.compile(r"\d+\.\d+\.\d+\.\d+")
    pattern2=re.compile(r"\w+\.txt")

    
    for i in range(1,len(sys.argv)):
        print(sys.argv[i])
        if sys.argv[i]=="-d" or sys.argv[i]=="-D":
            debug_level=1
            continue
        if sys.argv[i]=="-dd" or sys.argv[i]=="-dD" or sys.argv[i]=="-Dd" or sys.argv[i]=="-DD":
            debug_level=2
            continue
        if pattern1.match(sys.argv[i]):
            DNS_IP=sys.argv[i]
            continue
        if pattern2.match(sys.argv[i]):
            profile=sys.argv[i]
            continue
    print("Name sever ",DNS_IP,':',PORT)
    print("Debug level ",debug_level)
    #检测配置是否可用
    not_ping= os.system('ping -n 2 -w 1 '+DNS_IP)
    if not_ping:
        instruction = input("外部DNS无法ping通，可能该DNS地址不正确，是否继续？Y/N")
        if instruction == 'N' or instruction == 'n':
            return 0
    try:
        fp=open(profile,"r")
        for i in fp:
            if i =='\n':
                continue
            ip,key=i.split()
            if debug_level == 2:
                print(ip,key)
            data[key]=ip
    except IOError:
        print("配置文件不存在\n")
        return 0
    print('\n')
    return 1




'''
            analysis_information()根据调试等级解析报头
1.当调试等级为0或1时（debug_level==0），只需要确定head_ID,domain_name 和 TYPE，CLASS就行
2.当调试等级为2时，需要详细的解析出报头的各个部分

'''
def analysis_information(msg):
    #global head_ID,domain_name,TYPE
    data_dic = {}
    if debug_level >2 or debug_level<0:
        return data_dic
    seq1 = ('head_ID', 'domain_name', 'TYPE','CLASS')
#调试等级为1或0时需返回的数据存入dict1字典里
    dict1 = dict.fromkeys(seq1)
    dict1['head_ID'] = msg[0:2]
    #head_ID = dict1['head_ID']
    #dict1['domain_name'] = msg[12:16]
    dict1['TYPE'] =  msg[-4]+msg[-3]
    #TYPE = dict1['TYPE']
    dict1['CLASS'] = msg[-2]+msg[-1]
    thelen = msg[12]
    i = 12
    dict1['domain_name'] = ''
    while thelen != 0:
        dict1['domain_name']= dict1['domain_name']+str(msg[i+1:i+1+thelen])[2:-1]+'.'
        i = i+thelen+1
        thelen=msg[i]
    #dict1['domain_name'] =( dict1['domain_name'][:-1]).encode()
    dict1['domain_name']=dict1['domain_name'][:-1]
    #os.system("pause")
    #domain_name = dict1['domain_name']
    data_dic.update(dict1)

    #调试等级为2时，将报头的各个部分除了已经加到字典dict1加入到字典dict2中
    if debug_level == 2:
        seq2 = ('QR', 'OPCODE', 'AA', 'TC','RD','RA','Z','RCODE','QDCOUNT','ANCOUNT','NSCOUNT','ARCOUNT')
        dict2 = dict.fromkeys(seq2)
        data = msg[2]
        flags = ''.join([str(int(data / 2 ** (7 - i))) for i in range(8)])
        dict2['QR'] = flags[0]
        dict2['OPCODE'] = flags[1:5]
        dict2['AA'] = flags[5]
        dict2['TC'] = flags[6]
        dict2['RD'] = flags[7]

        data = msg[3]
        flags = ''.join([str(int(data / 2 ** (7 - i))) for i in range(8)])
        dict2['RA'] = flags[0]
        dict2['Z'] = flags[1:4]
        dict2['RCODE'] = flags[4:]
        dict2['QDCOUNT'] = msg[4]+msg[5]
        dict2['ANCOUNT'] = msg[6]+msg[7]
        dict2['NSCOUNT'] = msg[8]+msg[9]
        dict2['ARCOUNT'] = msg[10]+msg[11]
        data_dic.update(dict2)
    return data_dic




'''
        deal_question()处理从客户端发来的查询报文
1.如果TYPE类型为其它时，就直接进行ID转换（将对应信息记录在ID字典里），将转化ID后的报文发送给DNS服务器
2.如果TYPE类型为1，就以域名为key从字典中查询对应的IP，找到了就返回相应信息（注意IP为0.0.0.0的情况），找不到就ID转换一下（将对应信息记录在ID字典里），发送给DNS服务器
3.ID转化后需要把新ID和发送时间追加到TIME列表里
'''
def deal_question(client_IP, client_port,head_ID,TYPE,domain_name,msg):
    global ID,TIME, s,data,DNS_IP
    if TYPE == 1:
        if domain_name in data.keys():
            if data[domain_name] == '0.0.0.0':
                bytes_1 = msg[0:2]#id 16bit
                #flags
                bytes_2 = msg[2:4]# response+opcode 16bit
                temp=bytes_2.hex()#转成字符串
                QR=hex(int(temp[0],16)+8)#置QR为1
                RD = hex(int(temp[2], 16) + 8)  # 置RD为1
                rcode = hex(3)#域名不存在
                #问题数、资源数、授权数、额外
                bytes_3=msg[4:6]
                bytes_4=b'\x00\x00'
                bytes_5=b'\x00\x00'
                bytes_6=b'\x00\x00'
                # 头部
                head=bytes_1+bytes.fromhex(QR[2]+temp[1]+RD[2]+rcode[2])+bytes_3+bytes_4+bytes_5+bytes_6
                inquiry=msg[12:]#查询部分
                # 生成应答报文并发送
                answermsg=head+inquiry
                #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(answermsg, (client_IP,client_port))
            else:
                # 生成应答报文
                bytes_1 = msg[0:2]  # id 16bit
                # flags
                bytes_2 = msg[2:4]  # response+opcode 16bit
                temp = bytes_2.hex()  # 转成字符串
                QR = hex(int(temp[0], 16) + 8)  # 置QR为1
                RD = hex(int(temp[2], 16) + 8)  # 置RD为1
                rcode = hex(0)  # 无错误
                # 问题数、资源数、授权数、额外
                bytes_3 = msg[4:6]
                bytes_4 = b'\x00\x01'
                bytes_5 = b'\x00\x01'
                bytes_6 = b'\x00\x00'
                # 头部
                head = bytes_1 + bytes.fromhex(QR[2] + temp[1] + RD[2] + rcode[2]) + bytes_3 + bytes_4 + bytes_5 + bytes_6
                inquiry = msg[12:]  # 查询部分
                #应答部分
                deviation=b'\xc0\x0c'
                # 查询类型、查询类
                inqtype=b'\x00\x01'
                inqclass=b'\x00\x01'
                #生存时间
                ttl=b'\x00\x00\x00\x27'
                #资源长度
                sourcelen=b'\x00\x04'
                #ip地址
                ip=data[domain_name]
                packed_ip_addr=socket.inet_aton(ip)
                #生成应答报文并发送
                answermsg=head+inquiry+deviation+inqtype+inqclass+ttl+sourcelen+packed_ip_addr
                #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(answermsg,(client_IP,client_port))
        else:
            transid1 = random.randint(0, 255)
            transid2 = random.randint(0,255)
            transid1=chr(transid1).encode('latin1')
            transid2=chr(transid2).encode('latin1')
            transid=transid1+transid2
            # 更新ID（client_IP, client_port, client_ID）
            ID[transid] = [client_IP, client_port, head_ID]
            newmsg = transid+msg[2:]
            #newmsg[0:2] = transid
            #向dns发送报文
            #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            #更新TIME
            TIME.append([transid,time.time()])
            s.sendto(newmsg, (DNS_IP, 53))
            if debug_level == 2:
                print("SEND to ",DNS_IP,':',53,"(",len(newmsg),' bytes) [ID ',head_ID,'->',transid,']')
    else:
        transid1 = random.randint(0, 255)
        transid2 = random.randint(0, 255)
        transid1 = chr(transid1).encode('latin1')
        transid2 = chr(transid2).encode('latin1')
        transid = transid1 + transid2
        # 更新ID（client_IP, client_port, client_ID）
        ID[transid] = [client_IP, client_port, head_ID]
        newmsg = transid+msg[2:]
        #newmsg[0:2] = transid
        #向dns发送报文
        #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #更新TIME
        TIME.append([transid, time.time()])
        s.sendto(newmsg, (DNS_IP, 53))
        if debug_level == 2:
            print("SEND to ",DNS_IP,':',53,"(",len(newmsg),' bytes) [ID ',head_ID,'->',transid,']')
       
    return



'''
        deal_answer()处理从DNS返回的回答报文--刘忠新
1.从报头找出ID，根据ID查找ID字典中有没有对应的信息
2.如果没找到就算了
3.如果找到了，就把该ID转化为原ID发送给客户端，并将TIME列表里的对应信息删除
'''
def deal_answer(msg):
    global ID,TIME,lock,s
    my_id=msg[0:2]
    if my_id in ID.keys():
        M=ID[my_id][2]
        M+=msg[2:]
        s.sendto(M,(ID[my_id][0],ID[my_id][1]))
        if debug_level == 2:
            print("SEND to ",ID[my_id][0],':',ID[my_id][1],"(",len(M),' bytes) [ID ',my_id,'->',ID[my_id][2],']')
        while(lock):
            continue
        lock=1
        for i in range(len(TIME)):
            if TIME[i][0]==my_id:
                del TIME[i]
                ID.pop(my_id)#移除DATA字典中元素
                lock=0
                break
    return


'''
        count_time() 计时进程--刘忠新
每隔一定时间处理TIME列表，超时的元素进行删除并调用out_time(id)函数
'''
def count_time():
    global TIME,lock,time_delay
    while(1):
        while(lock):    #获取锁
            continue
        lock=1
        now=time.time()    #获取当前时间
        for i in TIME:    #检查每个TIME元素
            if now - i[1] > time_delay:
                out_time(i[0])
                TIME.remove(i)
        lock=0    #释放锁
        time.sleep(time_delay/100)

    return 



'''
        out_time(id)超时报告函数--刘忠新
根据该id从ID字典中找到对应的客户端IP，port和原报文ID，向客户端报告超时，并将该ID对应信息删除
'''
def out_time(id):
    global ID

    before_id=ID[id][2]
    error_bytes=b'\x81\x83'

    m=before_id+error_bytes
    s.sendto(m,(ID[id][0],ID[id][1]))
    print("SEND TO ",ID[id][0],":",ID[id][1],"out of time message.")
    #将该id 在ID字典中删除
    del ID[id]
    return


'''
          output(inf)打印详细信息的函数
'''
def output(inf):
    global debug_level,sequence
    if debug_level>=1:
        print(sequence,':',time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())," 域名:",inf['domain_name'],"  TYPE：",inf ['TYPE'],"  CLASS：",inf ['CLASS'])
    if debug_level==2:
        print("\tID ",inf['head_ID'],'QR',inf ['QR'], 'OPCODE',inf ['OPCODE'], 'AA',inf ['AA'], 'TC',inf ['TC'],'RD',inf ['RD'],'RA',inf ['RA'],'Z',inf ['Z'],'RCODE',inf ['RCODE'])
        print('\tQDCOUNT',inf ['QDCOUNT'],'ANCOUNT',inf ['ANCOUNT'],'NSCOUNT',inf ['NSCOUNT'],'ARCOUNT',inf ['ARCOUNT'])
    sequence+=1
'''
                主函数
'''
    

def deal_Q(client_IP,client_port,msg):
    inf=analysis_information(msg)
    output(inf) 
    deal_question(client_IP,client_port,inf['head_ID'],inf['TYPE'],inf['domain_name'],msg,)

if __name__ == '__main__':
    #初始化
    if(not init()):
        print("初始化失败......")
        os.system("pause")
        sys.exit()

    
    _thread.start_new_thread(count_time,())
    while True:
        #数据包身份确认（已完成）
 
        try:
            msg , (client_IP,client_port) = s.recvfrom(1024)
        except:
 
            continue
        
        #打印调试信息（已完成）
        if debug_level==2:
            print("RECV from "+str(client_IP)+": "+str(client_port)+"("+str(len(msg))+"bytes"+")") 
            for i in msg:
                print(str(i)+' ',end='')
            print('\n')
        
        #对于来自于DNS服务器的应答报文
        if client_port==53:
            _thread.start_new_thread(deal_answer,(msg,))

        #对于来自客户端的询问报文
        else:
            #根据调试等级解析报头
            _thread.start_new_thread(deal_Q,(client_IP,client_port,msg,))
