# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract err function (return-sensitive function)
# -----------------------------

# import sys
import os
import argparse
import datetime
from mining_errFunc import MiningErrFunc
from extract_errFunc_feature import ExtractErrFunFeatures
from database_provider import DBContentsProvider
from ObjDataAndBinFile import ObjDataAndBinFile
from config import *
import datetime

# sys.path.append("..")

class MiningErrfuncShell:

    def __init__(self):
        self.db_provider = DBContentsProvider()
        parser = argparse.ArgumentParser(description='识别源代码项目中的返回值敏感性函数')
        parser.add_argument('-t', "--type", required=True, type=str, choices=["select","all"],
                            help='select:只对config.py中设置的函数进行识别\n all:对源代码项目中所有的函数进行识别')
        #parser.add_argument("-t", "--threshold", required=False, type=int, default=0.5,
        #                    help="the threshold of the entropy")
        self.args = parser.parse_args()

    def set_fuctions_bechecked(self):
        func_list = []
        if self.args.type == "all":
            func_list = self.db_provider.query_allCallee_name()
        elif self.args.type == "select":
            func_list = G_func_list
        # 删除列表中出现在G_func_unnormal中的异常函数，即Joern无法处理的函数
        for item in G_func_unnormal:
            if item in func_list:
                func_list.remove(item)
        return func_list

    def check_func(self,function_name):
        function_name_str = function_name.encode('gbk')
        #
        datapath = G_feature_path+"/%s.data"%function_name_str
        if os.path.exists(datapath):
            #filename = "Data/42153.data"
            feature_callees = ObjDataAndBinFile.binfile2objdata(datapath)
        else:
            extract_errfun_feature = ExtractErrFunFeatures(function_name_str)
            #patterns = extract_check_patterns.run(False, callee_ids)
            feature_callees = extract_errfun_feature.run(flag_thread=False)

        obj_MiningErrFunc = MiningErrFunc(feature_callees)
        #mining_result = [is_err, weight_call, ratio_ft_path,ratio_ft_stmt,ratio_ft_usedOneside]
        mining_result = obj_MiningErrFunc.run()
        tmp = []
        tmp.append(function_name)
        tmp.extend(mining_result)
        return tmp

    def write_info(self, filepath, info):
        f= open(filepath,'a' )
        f.write(info)
        f.close
        return

    def run(self):
        allCallee_name = self.set_fuctions_bechecked()
        display_data = []
        num_func = len(allCallee_name)
        num_alalysed_func = 0
        infoSaved = "\nBeginTime = %s   num_func = %s\n"%(datetime.datetime.now(),num_func)
        self.write_info(G_debug_path,infoSaved)

        for function_name in allCallee_name:
            tmp = []
            tmp = self.check_func(function_name)
            display_data.append(tmp)
            num_alalysed_func = num_alalysed_func +1
            infoSaved = str(tmp[1]) + str("  ") + str(tmp[2]) + "  " +  str(tmp[0])
                            + "  " +  str(tmp[3])+ "  " +  str(tmp[4])+ " "  + str(tmp[5])
            self.write_info(G_debug_path,infoSaved)

        infoSaved = "EndTime = %s   num_alalysed_func = %s\n"%(datetime.datetime.now(),num_alalysed_func)
        self.write_info(G_debug_path,infoSaved)

        display_data = sorted(display_data, key=lambda l: (l[1],l[2]), reverse=True)
        # 保存数据
        f= open("Data/10141859.txt",'w' )
        #f= open("Data/%s.data"%int(time.time),'w' )
        for data in display_data:
            f.write(str(data[0]) + str("  ") + str(data[1]) + "  " +  str(data[2])
                    + "  " +  str(data[3])+ "  " +  str(data[4]) + " " + str(data[5]))
            f.write("\n")
        f.close()


        ##debug：缺陷检测部分,检测前面num_detect个fun
        num_detect = 50
        index = 0
        for func_item in display_data:
            function_name_str = func_item[0].encode('gbk')
            extract_errfun_feature = ExtractErrFunFeatures(function_name_str)
            #patterns = extract_check_patterns.run(False, callee_ids)
            feature_callees = extract_errfun_feature.run(flag_thread=False)
            for ft_callee in feature_callees:
                ft_info = "%s %s %s %s %s %s %s %s"%(func_item[0],ft_callee[0],ft_callee[2][0],ft_callee[2][1],
                            ft_callee[2][2],ft_callee[3][0], ft_callee[3][1],ft_callee[3][2])
                f_dectect= open("Data/detect.txt",'a' )
                f_dectect.write(ft_info)
                f_dectect.write("\n")
            index =index +1
            if index > num_func:
                break
        ##
        return



if __name__ == '__main__':

    import datetime
    start_time = datetime.datetime.now()
    print "\nBegin time: %s \n" % start_time
    obj_MiningErrfuncShell = MiningErrfuncShell()
    obj_MiningErrfuncShell.run()
    end_time = datetime.datetime.now()
    print "\nTime Used: %s" % (end_time - start_time)


