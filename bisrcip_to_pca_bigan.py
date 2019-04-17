import os
from collections import defaultdict
import numpy as np
import time,datetime
bydate_max=50#bydate_list中最大下标+1
label={}#存放所有连接的源ip
serv_prot={}#存储服务和协议
time_window=6#时间窗口的大小这里先设为5min
time_window_num=10#时间窗口的数量
#针对18数据集的还不完整，需要svm相关的操作

#删除文件夹下的所有文件
def  del_file(path):
    for i in os.listdir(path):
        path_file = os.path.join(path,i)  ##取文件绝对路径
        if os.path.isfile(path_file):
            os.remove(path_file)
        else:
            del_file(path_file)

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
    return dic

def new_slot_attack():
    dic=defaultdict(lambda :0)
    for i in range(1, time_window_num + 1):
        dic[i] = []
    return dic

def new_slot_desip():
    dic = defaultdict(lambda: 0)
    for i in range(1, time_window_num + 1):
        dic[i] = []
    return dic

def new_slot_all_desip():
    dic = defaultdict(lambda: 0)
    for i in range(1, time_window_num + 1):
        dic[i] = []
    return dic

def new_label():
    dic=defaultdict(lambda: 0)
    for i in range(1, time_window_num + 1):
        dic[i] = 0
    return dic

#将时间转变为stamp类型
def time_to_stamp(s):
    if (len(s.split(":"))==2):
        time_array = time.strptime(s, "%d/%m/%Y %H:%M")
        stamp = int(time.mktime(time_array))
        return stamp
    else:
        time_array = time.strptime(s, "%d/%m/%Y %H:%M:%S")
        stamp = int(time.mktime(time_array))
        return stamp


def time_to_stamp2(s):
    time_array=time.strptime(s,"%d/%m/%Y %H:%M")
    stamp=int(time.mktime(time_array))
    return stamp

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
        t=sorted(f_tem,key=lambda s: time_to_stamp(s.split(",")[6]),reverse=0)
        f_tem = open('bysrcip_list/' + line,"w")
        for i in t:
            f_tem.write(i)

# sort_file()


def time_partition(attack_name):
    file_name='18_pca_bigan_add/'
    f=open('bysrcip_list/all_src_ip')
    w_norm = open(file_name+'n','w')
    w_norm_label = open(file_name+'n_label', 'w')
    w_norm_ip = open(file_name+'n_ip',"w")
    w_norm_slot_attack=open(file_name+'n_slot_attack',"w")
    w_norm_slot_desip=open(file_name+'n_slot_desip',"w")
    w_norm_slot_all_desip = open(file_name+'n_slot_all_desip', "w")

    w_anom = open(file_name+'a', 'w')
    w_anom_label = open(file_name+'a_label', 'w')
    w_anom_ip= open(file_name+'a_ip',"w")
    attack_name_s=attack_name.replace(" ","_")
    w_anom_attack=open(file_name+attack_name_s+'a_attack',"w")#保存异常窗口中是否含有某种攻击, 这里先尝试warezclient
    w_anom_slot_attack = open(file_name+'a_slot_attack', "w")
    w_anom_slot_desip = open(file_name+'a_slot_desip', "w")
    w_anom_slot_all_desip = open(file_name+'a_slot_all_desip', "w")

    w_test= open("feature_test","a")

    anomaly_wins=0

    for line in f.readlines():
        line=line.strip()
        f_tem=open('bysrcip_list/'+line)

        """
        w_norm.write(line+'\n')
        w_anom.write(line+'\n')
        w_norm_label.write(line+'\n')
        w_anom_label.write(line+'\n')
        """
        win_start_time=0#上一个全部时间窗口的起始时间,stamp时间
        dic = defaultdict(lambda: defaultdict(lambda: 0))  # 声明一个二维dict
        dic_label=defaultdict(lambda: 0)#存放每个时间窗口是否为异常
        dic_slot_attack=defaultdict(lambda: 0)#存放每个时间槽出现的所有攻击
        dic_slot_desip=defaultdict(lambda: 0)#存放每个时间槽中出现的攻击对应的目标IP
        is_attack=0
        is_anom=0
        for line_tem in f_tem.readlines():

            # #testing!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            # attack=line_tem.strip().split()[-1]
            # if(attack==attack_name):
            #     continue

            date=line_tem.split(",")[6]
            print(date)
            date_stamp=time_to_stamp(date)
            if(date_stamp-win_start_time>=time_window*time_window_num):
                if(win_start_time!=0):
                    for key,value1 in dic.items():
                        s=[]
                        #w_test.write(key+" ")
                        for key2,value in value1.items():
                            s.append(str(value))
                        string=" ".join(s)
                        if(is_anom==1):
                            w_anom.write(string+'\n')
                            anomaly_wins+=1
                        elif(is_anom==0):
                            w_norm.write(string+'\n')
                    #w_test.write("\n")
                    s_label=[]
                    for key,value in dic_label.items():
                        s_label.append(str(value))
                    string=" ".join(s_label)
                    if(is_anom==1):
                        w_anom_label.write(string+"\n")
                        w_anom_ip.write(line+"\n")
                        w_anom_attack.write(str(is_attack)+"\n")
                    else:
                        w_norm_label.write(string+"\n")
                        w_norm_ip.write(line+"\n")


                    for key,value in dic_slot_attack.items():
                        if (len(value) == 0):
                            string = '0'
                        else:
                            string = ",".join(value)
                        if (is_anom == 1):
                            w_anom_slot_attack.write(string)
                            w_anom_slot_attack.write('\n')
                        else:
                            w_norm_slot_attack.write(string)
                            w_norm_slot_attack.write('\n')

                    #     if(len(value)==0):
                    #         s.append("0")
                    #     else:
                    #         s += value
                    #     s.append("\n")
                    #
                    # string=",".join(s)
                    # if(is_anom==1):
                    #     w_anom_slot_attack.write(string)
                    # else:
                    #     w_norm_slot_attack.write(string)

                    for key,value in dic_slot_desip.items():
                        if (len(value) == 0):
                            string = '0'
                        else:
                            string = ",".join(value)
                        if (is_anom == 1):
                            w_anom_slot_desip.write(string)
                            w_anom_slot_desip.write('\n')
                        else:
                            w_norm_slot_desip.write(string)
                            w_norm_slot_desip.write('\n')

                    for key, value in dic_slot_all_desip.items():
                        if (len(value) == 0):
                            string = '0'
                        else:
                            string = ",".join(value)
                        if (is_anom == 1):
                            w_anom_slot_all_desip.write(string)
                            w_anom_slot_all_desip.write('\n')
                        else:
                            w_norm_slot_all_desip.write(string)
                            w_norm_slot_all_desip.write('\n')



                #重新初始化一个windows
                win_start_time = date_stamp
                dic=new_matrix()
                dic_label=new_label()
                is_anom=0
                is_attack=0
                dic_slot_attack=new_slot_attack()
                dic_slot_desip=new_slot_desip()
                dic_slot_all_desip = new_slot_all_desip()
            #
            #print(line_tem)
            attack = line_tem.strip().split(',')[-1]
            if(attack.strip()==attack_name):
                is_attack=1
            service=line_tem.strip().split(',')[5]
            service=float(service)
            service=int(service)
            service=str(service)
            # if(":" in service ==True):
            #     service=service.split(":")[0]
            print('date_stamp')
            print(date_stamp)
            print(win_start_time)

            window = int((date_stamp - win_start_time) / time_window) + 1
            print(service)
            print(window)
            if service in dic:
                dic[service][window]+=1
            # if service.isdigit()==True:
            #     if "/u" in service:
            #         dic["digit/u"][window]+=1
            #     else:dic["digit"][window]+=1
            # if "/u" in service:
            #     dic["udp"][window]+=1
            # elif "/i" in service:
            #     dic["icmp"][window]+=1
            # else:dic["tcp"][window]+=1
            dura=line_tem.strip().split(',')[7]
            dura=float(dura)
            dic["duration"][window]+=dura
            desip=line_tem.strip().split(',')[3]
            if(line_tem.strip().split(',')[-1]=='BENIGN' or line_tem.strip().split(',')[-1]=='Benign'):
                is_a=0
            else:
                is_a=1
            if is_a==1:
                is_anom=1
                dic_label[window]=is_a
                if(attack not in dic_slot_attack[window]):
                    dic_slot_attack[window].append(str(attack))
                # if(desip not in dic_slot_desip[window]):
                #     dic_slot_desip[window].append(str(desip))
                dic_slot_desip[window].append(str(desip))

            dic_slot_all_desip[window].append(str(desip))

            for i in range(8,84):
                fwd_total = line_tem.strip().split(",")[i]
                fwd_packet = float(fwd_total)
                name='total'+str(i)
                dic[name][window] += fwd_packet


            # fwd_total=line_tem.strip().split(",")[8]
            # fwd_packet=line_tem.strip().split(",")[10]
            # fwd_packet=int(float(fwd_packet))
            # fwd_total=int(float(fwd_total))
            # dic['Total_5'][window]+=fwd_total
            # dic['Total_7'][window]+=fwd_packet




        #don't forget 保存最后一个窗口
        for key,value1 in dic.items():
            s = []
            #w_test.write(key + " ")
            for key2, value in value1.items():
                s.append(str(value))
            string = " ".join(s)
            if (is_anom == 1):
                w_anom.write(string + '\n')

                anomaly_wins += 1

            if (is_anom == 0):
                w_norm.write(string + '\n')
        #w_test.write("\n")
        s_label = []
        for key, value in dic_label.items():
            s_label.append(str(value))
        string = " ".join(s_label)
        if (is_anom == 1):
            w_anom_label.write(string + "\n")
            w_anom_ip.write(line + "\n")
            w_anom_attack.write(str(is_attack)+"\n")
        else:
            w_norm_label.write(string + "\n")
            w_norm_ip.write(line + "\n")

        for key, value in dic_slot_attack.items():
            if(len(value)==0):
                string='0'
            else:
                string = ",".join(value)

            if (is_anom == 1):
                w_anom_slot_attack.write(string)
                w_anom_slot_attack.write('\n')
            else:
                w_norm_slot_attack.write(string)
                w_norm_slot_attack.write('\n')

        #     if(len(value)==0):
        #         s.append("0")
        #     else:
        #         s += value
        #     s.append("\n")
        #
        # string=",".join(s)
        # if(is_anom==1):
        #     w_anom_slot_attack.write(string)
        # else:
        #     w_norm_slot_attack.write(string)

        for key, value in dic_slot_desip.items():
            if (len(value) == 0):
                string = '0'
            else:
                string = ",".join(value)
            if (is_anom == 1):
                w_anom_slot_desip.write(string)
                w_anom_slot_desip.write('\n')
            else:
                w_norm_slot_desip.write(string)
                w_norm_slot_desip.write('\n')

        for key, value in dic_slot_all_desip.items():
            if (len(value) == 0):
                string = '0'
            else:
                string = ",".join(value)
            if (is_anom == 1):
                w_anom_slot_all_desip.write(string)
                w_anom_slot_all_desip.write('\n')
            else:
                w_norm_slot_all_desip.write(string)
                w_norm_slot_all_desip.write('\n')


#f=open('bysrcip_list/all_feature','a')
# for i in range(8,84):
#     f.write("total"+str(i)+'\n')

# f=open('bysrcip_list/all_src_ip')
# all_attack={}
# for line in f.readlines():
#     line=line.strip()
#     f_tem=open('bysrcip_list/'+line)
#     for line_tem in f_tem.readlines():
#         if(line_tem.strip().split(',')[-1] not in all_attack):
#             all_attack[line_tem.strip().split(',')[-1]]=1
# print(all_attack)

# for key,value in all_attack.items():
#     time_partition(key)
# time_partition('DoS GoldenEye')
    # w_test.write(attack_name+" "+str(anomaly_wins)+"\n")

#sort_file()
def get_serv_prot():
    serv_file={}
    list_a={}
    line_sum=0
    list_src={}
    list_des={}
    f=open('bysrcip_list/all_src_ip')
    for line in f.readlines():
        line=line.strip()
        f_tem=open('bysrcip_list/'+line)
        for line_tem in f_tem.readlines():
            line_sum += 1
            a=line_tem.strip().split(',')[-1]
            des=line_tem.strip().split(',')[1]
            src=line_tem.strip().split(',')[0]
            if(a not in list_a):
                list_a[a]=1
            else:list_a[a]+=1
            if(des not in list_des):
                list_des[des]=1

            if(src not in list_src):
                list_src[src]=1
    return line_sum,len(list_a)-2,len(list_src),len(list_des)
# dic=get_serv_prot()
# print(dic['warzclient'])
# print(dic['warezclient'])
# for key,value in dic.items():
#     time_partition(key)

# time_partition('warezclient')
character=95
time_windows=10
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tqdm import tqdm
from sklearn.utils import shuffle
from sklearn.decomposition import PCA


def loaddata(datafile):
    list1 = []
    for i in range(1, character+1):
        list1.append(str(i))
    return np.array(pd.read_csv(datafile,sep=" ",header=None,names=list1).astype(np.float))

def pca(name):#name = a or n 及其对应的行数
    #转置：
    data=np.loadtxt('18_pca_bigan_add/'+name,delimiter=" ")



    line_final_num=int(data.shape[0]/character)
    data_transpose=np.zeros(shape=(line_final_num*time_windows,character))
    for i in range(line_final_num):
        data_tem=data[i*character:(i+1)*character]
        data_tem_transpose=np.transpose(data_tem)
        data_transpose[i*time_windows:(i+1)*time_windows]=data_tem_transpose
    np.savetxt('18_pca_bigan_add/'+name+"_transpose",data_transpose)

    #pca
    pca = PCA(n_components=1)
    pca_data=loaddata('18_pca_bigan_add/'+name+"_transpose")
    from sklearn.preprocessing import Imputer
    pca_data = Imputer().fit_transform(pca_data)
    res=pca.fit_transform(pca_data)
    # print(res)
    array_res=np.array(res)
    res_line=int(line_final_num)#结果的行数
    name_result=np.zeros(shape=(res_line,time_windows))
    for i in range(0,res_line):
        tem=array_res[i*time_windows:(i+1)*time_windows]
        tem_transpose=np.transpose(tem)
        name_result[i]=tem_transpose
    np.savetxt('18_pca_bigan_add/' + name+"_pca_transpose", name_result)


def pca_all(name):  # \
    # 转置：
    data = np.loadtxt('18_pca_bigan_add/' + 'a', delimiter=" ")
    data_n=np.loadtxt('18_pca_bigan_add/' + 'n', delimiter=" ")

    data=np.concatenate([data,data_n],axis=0)

    line_final_num = int(data.shape[0] / character)
    data_transpose = np.zeros(shape=(line_final_num * time_windows, character))
    for i in range(line_final_num):
        data_tem = data[i * character:(i + 1) * character]
        data_tem_transpose = np.transpose(data_tem)
        data_transpose[i * time_windows:(i + 1) * time_windows] = data_tem_transpose
    np.savetxt('18_pca_bigan_add/' + name + "_transpose", data_transpose)

    # pca
    pca = PCA(n_components=1)
    pca_data = loaddata('18_pca_bigan_add/' + name + "_transpose")
    from sklearn.preprocessing import Imputer
    pca_data = Imputer().fit_transform(pca_data)
    res = pca.fit_transform(pca_data)
    # print(res)
    array_res = np.array(res)
    res_line = int(line_final_num)  # 结果的行数
    name_result = np.zeros(shape=(res_line, time_windows))
    for i in range(0, res_line):
        tem = array_res[i * time_windows:(i + 1) * time_windows]
        tem_transpose = np.transpose(tem)
        name_result[i] = tem_transpose
    np.savetxt('18_pca_bigan_add/' + 'a' + "_pca_transpose", name_result[:1006])
    np.savetxt('18_pca_bigan_add/' + 'n' + "_pca_transpose", name_result[1006:])

# data = pd.read_table('18_pca_bigan/a',header=None,delimiter=" ")
# data.columns=['1','2','3','4','5','6','7','8','9','10',]
# print(data.isnull().any())
# pca("a")
# pca("n")
pca_all('all')


# pca("a",273090)
# pca("n",82970)
# s1,s2,s3,s4=get_serv_prot()
# print(s1)
# print(s2)
# print(s3)
# print(s4)

# time_partition('warezclient')