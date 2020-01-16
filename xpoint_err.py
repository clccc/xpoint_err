# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract err function (return-sensitive function)
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
        #function_name_str = function_name.encode('gbk')
        #获取特征数据
        savedinfo = "获取%s的特征数据\n"%function_name
        write_info(gl.G_debuginfo_path,savedinfo)
        datapath = gl.G_prjdata_dir + "/%s.data" % function_name
        if os.path.exists(datapath):
            #filename = "Data/42153.data"
            datatmp = ObjDataAndBinFile.binfile2objdata(datapath)
            feature_callees = datatmp[0]
            flag_rvar_func = datatmp[1]
        else:
            extract_errfun_feature = ExtractErrFunFeatures(function_name)
            #patterns = extract_check_patterns.run(False, callee_ids)
            feature_callees,flag_rvar_func = extract_errfun_feature.run(flag_thread=False)

        # 挖掘返回值敏感型函数
        write_info(gl.G_debuginfo_path,"获取%s的识别结果\n"%function_name)
        obj_MiningErrFunc = MiningErrFunc(feature_callees)
        #mining_result = [callee_counts,is_err,
        # ratio_ft_check, ratio_ft_path,ratio_ft_stmt,ratio_ft_notusedTwoside]
        mining_result = obj_MiningErrFunc.run()
        # 修正返回值函数判断,若存在检查比例，显然具有返回值。其余保持原结果
        if mining_result[2] > 0:
            flag_rvar_func = 1
        xp_tmp = []
        xp_tmp.append(flag_rvar_func)
        xp_tmp.append(function_name)
        xp_tmp.extend(mining_result)
        #infoSaved = "%s %s %s %s %s %s %s"%(xp_tmp[1],xp_tmp[2],xp_tmp[3],xp_tmp[0],
        #                                   xp_tmp[3],xp_tmp[4],xp_tmp[5],xp_tmp[6])
        #infoSaved = str(xp_tmp[1]) + str("  ") + str(xp_tmp[2]) + "  " +  str(xp_tmp[0])\
        #            + "  " +  str(xp_tmp[3])+ "  " +  str(xp_tmp[4])+ " "  + str(xp_tmp[5])
        write_info(gl.G_debuginfo_path, xp_tmp)
        return xp_tmp


    def run(self):
        # 根据用户输入的项目名称，创建保存程序输出的文件夹
        result = make_dir(gl.G_prjdata_dir)
        write_info(gl.G_debuginfo_path, result)

        allCallee_name = self.set_fuctions_bechecked()
        xpoint_reasult = []
        num_func = len(allCallee_name)
        num_alalysed_func = 0
        infoSaved = "\n# *%s* 中返回值敏感型函数识别：\n起始时间 = %s  待识别函数数量 = %s"\
                    %(self.args.projectname, datetime.datetime.now(),num_func)
        write_info(gl.G_result_path, infoSaved)

        tmp_index = 0
        for function_name in allCallee_name:
            print "%d 识别%s\n"%(tmp_index,function_name)
            tmp_index = tmp_index + 1
            xp_tmp = []
            # 识别function_name
            #is_erFunc = [isVar funcname callee_counts,is_err,
            # ratio_ft_check, ratio_ft_path,ratio_ft_stmt,ratio_ft_notusedTwoside]
            xp_tmp = self.is_erFunc(function_name)
            xpoint_reasult.append(xp_tmp)
            num_alalysed_func = num_alalysed_func +1
        infoSaved = "结束时间 = %s   已分析函数数量 = %s\n"\
                    %(datetime.datetime.now(),num_alalysed_func)
        write_info(gl.G_result_path, infoSaved)

        xpoint_reasult = sorted(xpoint_reasult, key=lambda l: (l[3],l[1]), reverse=True)
        # 输出结果及统计数据
        num_rvarFun = 0 # 返回值函数个数
        num_errFun = 0  # 返回值敏感型函数个数
        write_info(gl.G_result_path, "识别结果：")
        write_info(gl.G_result_path, "函数名 counts, is_rVar, is_err, ratio_ft_path,"
                                     "ratio_ft_stmt,ratio_ft_usedOneside, is_rVarF")
        for xp_tmp in xpoint_reasult:
            infoSaved = "%s: %s %s %s %s %s %s %s"\
                        %(xp_tmp[1],xp_tmp[2],xp_tmp[0],
                          xp_tmp[3],xp_tmp[4],xp_tmp[5],xp_tmp[6],xp_tmp[7])
            write_info(gl.G_result_path, infoSaved)
            if xp_tmp[0] == 1:
                num_rvarFun = num_rvarFun +1
            if xp_tmp[3] == 1:
                num_errFun = num_errFun +1
        infoSaved = "返回值函数个数=%s, 返回值敏感型函数个数=%s\n"%(num_rvarFun,num_errFun)
        write_info(gl.G_result_path, infoSaved)
        wXLS = writeXLS()
        wXLS.write_excel(gl.G_result_xls, xpoint_reasult)
        """
        ##debug：缺陷检测部分,检测前面num_detect个fun
        num_detect = 50
        index = 0
        for func_item in xpoint_reasult:
            function_name_str = func_item[0].encode('gbk')
            extract_errfun_feature = ExtractErrFunFeatures(function_name_str)
            #patterns = extract_check_patterns.run(False, callee_ids)
            feature_callees,flag_rvar_func = extract_errfun_feature.run(flag_thread=False)
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
        """
        return



if __name__ == '__main__':

    import datetime
    start_time = datetime.datetime.now()
    print "\nBegin time: %s \n" % start_time
    obj_MiningErrfuncShell = MiningErrfuncShell()
    obj_MiningErrfuncShell.run()
    end_time = datetime.datetime.now()
    print "\nTime Used: %s" % (end_time - start_time)


