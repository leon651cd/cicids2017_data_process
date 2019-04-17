import os
from collections import defaultdict
import time,datetime
import pandas as pd
bydate_max=8#bydate_list中最大下标+1
label={}#存放所有连接的源ip
serv_prot={}#存储服务和协议
time_window=600#时间窗口的大小这里先设为5min
time_window_num=10#时间窗口的数量

#删除文件夹下的所有文件
def  del_file(path):
    for i in os.listdir(path):
        path_file = os.path.join(path,i)  ##取文件绝对路径
        if os.path.isfile(path_file):
            os.remove(path_file)
        else:
            del_file(path_file)

#删除list文件夹下的所有非list文件
def delete_extra_flies():
    for i in range(1,bydate_max):
        s1=str(i)+'.txt'
        s2=str(i)+'label.txt'
        if (os.path.exists(os.path.abspath('.')+'/bydate_list/'+s1) != True or os.path.exists(os.path.abspath('.')+'/bydate_list/'+s2) != True):
            continue
        os.remove(os.path.abspath('.')+'/bydate_list/'+s1)
        os.remove(os.path.abspath('.')+'/bydate_list/'+s2)

#对ip的形式进行调整，将无用的0去掉
def ip_zero(a):
    a0=int(a.split('.')[0])
    a1=int(a.split('.')[1])
    a2 = int(a.split('.')[2])
    a3 = int(a.split('.')[3])
    return str(a0)+'.'+str(a1)+'.'+str(a2)+'.'+str(a3)

#将bydate_list重新按照源ip划分生成bysrcip_list中的所有文件
def ip_list():
    del_file('bysrcip_list')
    w1=open('bysrcip_list/all_src_ip','w')#此文件中长期的保存所有的源ip **********
    column_list=['Flow ID', 'Source IP', 'Source Port', 'Destination IP',
       'Destination Port', 'Protocol', 'Timestamp', 'Flow Duration',
       'Total Fwd Packets', 'Total Backward Packets',
       'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
       'Fwd Packet Length Max', 'Fwd Packet Length Min',
       'Fwd Packet Length Mean', 'Fwd Packet Length Std',
       'Bwd Packet Length Max', 'Bwd Packet Length Min',
       'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
       'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
       'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
       'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
       'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
       'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
       'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
       'Idle Std', 'Idle Max', 'Idle Min', 'Label']
    for i in range(1,bydate_max+1):
        fname='data/'+str(i)+'.csv'
        if (os.path.exists(os.path.abspath('.') + '/data/' + str(i)+'.csv') != True):
            continue
        f=pd.read_csv(fname,encoding='ISO-8859-1')
        f.columns = f.columns.str.strip()
        print(fname)
        for key,line in f.iterrows():
            print(fname)
            print(key)
            srcip=line['Source IP']
            if(isinstance(srcip,str)) ==False:
                break
            if srcip not in label:
                label[srcip]=1
                w1.write(srcip+'\n')
            w=open('bysrcip_list/'+srcip,'a')
            line_list=[]
            for i in range(len(column_list)):
                line_list.append(str(line[column_list[i]]))


            string=",".join(line_list)

            print(string)
            w.write(string+'\n')
# ip_list()

#获得所有的服务和协议类型名称
def get_serv_prot():
    serv_file={}
    w=open('bysrcip_list/all_serv_prot','w')#此文件中长期的保存所有的服务和协议 **********
    f=open('bysrcip_list/all_src_ip')
    for line in f.readlines():
        line=line.strip()
        f_tem=open('bysrcip_list/'+line)
        for line_tem in f_tem.readlines():
            s_p=line_tem.strip().split()[2]
            isanom=line_tem.strip().split()[-2]
            if(s_p not in serv_prot):
                #w.write(s_p+'\n')
                serv_prot[s_p]=1
                serv_file[s_p]=isanom
            else:serv_prot[s_p]+=1
    test_data_3 = sorted(serv_prot.items(), key=lambda x: x[1], reverse=True)
    for i in test_data_3:
        w.write(str(i)+"\n")
    for k,v in serv_file.items():
        w.write(k+" "+str(v)+"\n")
    for i in test_data_3:
        w.write(str(i[0])+"\n")
#声明一个二维字典，每一行表示一个特征，每一列表示时间窗口
def new_matrix():
    dic = defaultdict(lambda: defaultdict(lambda: 0))  # 声明一个二维dict
    read_f=open('bysrcip_list/all_feature')#存放所有的feature
    for line in read_f.readlines():
        if(line.strip() not in dic):
            dic_1d={}
            for i in range(1,time_window_num+1):
                dic_1d[i]=0
            dic[line.strip()]=dic_1d
    print('初始化一个时间窗口，共有'+str(len(dic))+'个特征')
    return dic

def new_label():
    dic=defaultdict(lambda: 0)
    for i in range(1, time_window_num + 1):
        dic[i] = 0
    return dic

#将时间转变为stamp类型
def time_to_stamp(s):
    time_array=time.strptime(s,"%d/%m/%Y %H:%M:%S")
    stamp=int(time.mktime(time_array))
    return stamp

def time_to_stamp2(s):
    time_array=time.strptime(s,"%d/%m/%Y %H:%M")
    stamp=int(time.mktime(time_array))
    return stamp

# print(time_to_stamp('4/7/2017 4:41:0'))

#对bysrcip_list中的 时间 进行处理，有些不符合规范的如98改为1998
def process_file():
    f = open('bysrcip_list/all_src_ip')
    for line in f.readlines():
        line = line.strip()
        f_tem = open('bysrcip_list/' + line)
        old_data = f_tem.readlines()
        new_data = ''
        for i in old_data:
            items = i.split()
            date = items[1].split('/')
            year = date[2]
            if (int(year) < 100):
                newyear = '19' + year
                date[2] = newyear
            new_date = date[0] + '/' + date[1] + '/' + date[2]
            items[1] = new_date
            new_data += ' '.join(s for s in items)
            new_data += '\n'
        f_tem_w = open('bysrcip_list/' + line, 'w')
        f_tem_w.writelines(new_data)


#将bysrcip_list中的文件按照时间排序,这里的时间是stamp
def sort_file():
    f = open('bysrcip_list/all_src_ip')
    for line in f.readlines():
        line=line.strip()
        f_tem=open('bysrcip_list/' + line)
        t=sorted(f_tem,key=lambda s: time_to_stamp(s.split()[1]+' '+s.split()[2]),reverse=0)
        f_tem = open('bysrcip_list/' + line,"w")
        for i in t:
            f_tem.write(i)


#对每一个源节点进行时间窗划分和特征计算
def time_partition():
    f=open('bysrcip_list/all_src_ip')
    w_norm = open('18_pca_bigan/n','w')
    w_norm_label = open('18_pca_bigan/n_label', 'w')
    w_anom = open('18_pca_bigan/a', 'w')
    w_anom_label = open('18_pca_bigan/a_label', 'w')
    for line in f.readlines():
        line=line.strip()
        f_tem=open('bysrcip_list/'+line)
        print("current file:"+line)
        """
        w_norm.write(line+'\n')
        w_anom.write(line+'\n')
        w_norm_label.write(line+'\n')
        w_anom_label.write(line+'\n')
        """
        win_start_time=0#上一个全部时间窗口的起始时间,stamp时间
        dic = defaultdict(lambda: defaultdict(lambda: 0))  # 声明一个二维dict
        dic_label=defaultdict(lambda: 0)#存放每个时间窗口是否为异常
        is_anom=0
        for line_tem in f_tem.readlines():
            date=line_tem.strip().split()[1]
            time=line_tem.strip().split()[2]
            date=date+" "+time
            date_stamp=time_to_stamp(date)
            if(date_stamp-win_start_time>=time_window*time_window_num):
                if(win_start_time!=0):
                    for key,value1 in dic.items():
                        s=[]
                        for key2,value in value1.items():
                            s.append(str(value))
                        string=" ".join(s)
                        if(is_anom==1):
                            w_anom.write(string+'\n')
                        elif(is_anom==0):
                            w_norm.write(string+'\n')
                    s_label=[]
                    for key,value in dic_label.items():
                        s_label.append(str(value))
                    string=" ".join(s_label)
                    if(is_anom==1):
                        w_anom_label.write(string+"\n")
                    else:
                        w_norm_label.write(string+"\n")
                #重新初始化一个windows
                win_start_time = date_stamp
                dic=new_matrix()
                dic_label=new_label()
                is_anom=0
            #
            #print(line_tem)
            service=line_tem.strip().split()[4]
            if(":" in service ==True):
                service=service.split(":")[0]
            window = int((date_stamp - win_start_time) / time_window) + 1
            if service in dic:
                dic[service][window]+=1
            if service.isdigit()==True:
                if "/u" in service:
                    dic["digit/u"][window]+=1
                else:dic["digit"][window]+=1
            if "/u" in service:
                dic["udp"][window]+=1
            elif "/i" in service:
                dic["icmp"][window]+=1
            else:dic["tcp"][window]+=1
            dura=line_tem.strip().split()[3]
            dura=int(dura.split(":")[0])*3600+ int(dura.split(":")[1])*60+int(dura.split(":")[2])
            dic["duration"][window]+=dura
            is_a=int(line_tem.split()[-2])
            if is_a==1:
                is_anom=1
                dic_label[window]=is_a


        #don't forget 保存最后一个窗口
        for key,value1 in dic.items():
            s = []
            for key2, value in value1.items():
                s.append(str(value))
            string = " ".join(s)
            if (is_anom == 1):
                w_anom.write(string + '\n')
            if (is_anom == 0):
                w_norm.write(string + '\n')
        s_label = []
        for key, value in dic_label.items():
            s_label.append(str(value))
        string = " ".join(s_label)
        if (is_anom == 1):
            w_anom_label.write(string + "\n")
        else:
            w_norm_label.write(string + "\n")





#delete_extra_flies()
#del_file('bysrcip_list')
#ip_list()
#get_serv_prot()
#print(serv_prot)
#test_data_3=sorted(serv_prot.items(),key=lambda x:x[1],reverse=True)
#print(test_data_3)
#print(serv_prot)
#new_matrix()
#print(str(time_to_stamp("06/01/1998 21:31:01")))
#print(str(time_to_stamp("06/01/1998 21:31:04")))
#process_file()
#sort_file()
# time_partition()
# fname='data/4.csv'
# f=pd.read_csv(fname,nrows=5)
# print(f[' Flow Duration'])

# f.columns=f.columns.str.strip()
# # for key,value in f.iterrows():
# #     print(value[' Label'])
# print(f.columns)
# for key,value in f.iterrows():
#     if(key<50):
#         print(value['Label'])

column_list=['Flow ID', 'Source IP', 'Source Port', 'Destination IP',
       'Destination Port', 'Protocol', 'Timestamp', 'Flow Duration',
       'Total Fwd Packets', 'Total Backward Packets',
       'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
       'Fwd Packet Length Max', 'Fwd Packet Length Min',
       'Fwd Packet Length Mean', 'Fwd Packet Length Std',
       'Bwd Packet Length Max', 'Bwd Packet Length Min',
       'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
       'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
       'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
       'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
       'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
       'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
       'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
       'Idle Std', 'Idle Max', 'Idle Min', 'Label']
print(len(column_list))