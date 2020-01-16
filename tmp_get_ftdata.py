# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract err function (return-sensitive function)
# 电脑内存太小，此程序只是为了应急，提取函数的特征。可删
# -----------------------------

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import os
import argparse
import datetime
from mining_errFunc import MiningErrFunc
from extract_errFunc_feature import ExtractErrFunFeatures
from database_provider import DBContentsProvider
from ObjDataAndBinFile import ObjDataAndBinFile
import config as gl
from xutil import *
from writeXLS import writeXLS
import datetime

# sys.path.append("..")

class MiningErrfuncShell:

    def __init__(self):
        self.db_provider = DBContentsProvider()
        parser = argparse.ArgumentParser(description='识别源代码项目中的返回值敏感型函数')
        parser.add_argument('-t', "--type", required=True, type=str, choices=["select","all"],
                            help='select:只对config.py中设置的函数进行识别\n all:对源代码项目中所有的函数进行识别')
        parser.add_argument("-prj", "--projectname", required=True, type=str,
                            help="待识别函数所在的源代码项目，将以此建立同名数据文件夹")
        self.args = parser.parse_args()

        gl.G_prjdata_dir = "%s/%s"%(gl.G_alldata_dir,self.args.projectname)
        gl.G_result_path = "%s/%s"%(gl.G_prjdata_dir,"xp_err.txt")
        gl.G_debuginfo_path = "%s/%s"%(gl.G_prjdata_dir,"degbug.txt")
        gl.G_result_xls = "%s/%s"%(gl.G_prjdata_dir,"report.xls")

    def set_fuctions_bechecked(self):
        func_list = []
        if self.args.type == "all":
            func_list = self.db_provider.query_allCallee_name()
        elif self.args.type == "select":
            func_list = gl.G_func_list
        # 删除列表中出现在gl.G_func_unnormal中的异常函数，即Joern无法处理的函数
        for item in gl.G_func_unnormal:
            if item in func_list:
                func_list.remove(item)
        return func_list

    #result = [isVar funcname callee_counts,is_err,
    # ratio_ft_check, ratio_ft_path,ratio_ft_stmt,ratio_ft_notusedTwoside]
    def is_erFunc(self, function_name):
        datapath = gl.G_prjdata_dir + "/%s.data" % function_name
        if os.path.exists(datapath):
            #filename = "Data/42153.data"
            return
        else:
            extract_errfun_feature = ExtractErrFunFeatures(function_name)
            #patterns = extract_check_patterns.run(False, callee_ids)
            feature_callees,flag_rvar_func = extract_errfun_feature.run(flag_thread=False)
        return


    def run(self):
        # 根据用户输入的项目名称，创建保存程序输出的文件夹
        result = make_dir(gl.G_prjdata_dir)
        write_info(gl.G_debuginfo_path, result)
        allCallee_name = self.set_fuctions_bechecked()
        num_func = len(allCallee_name)
        tmp_index = 0
        for function_name in allCallee_name:
            print "%d-%d 识别%s\n"%(num_func,tmp_index,function_name)
            tmp_index = tmp_index + 1
            self.is_erFunc(function_name)
        return



if __name__ == '__main__':

    import datetime
    start_time = datetime.datetime.now()
    print "\nBegin time: %s \n" % start_time
    obj_MiningErrfuncShell = MiningErrfuncShell()
    obj_MiningErrfuncShell.run()
    end_time = datetime.datetime.now()
    print "\nTime Used: %s" % (end_time - start_time)


