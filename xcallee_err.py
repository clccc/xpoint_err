# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract err function (return-sensitive function)
# 不算entropy，只获取行为向量，entropy计算后续增加。
# -----------------------------

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import os
import argparse
import datetime
from mining_xCallee_err import MiningxCalleeErr
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
        gl.G_xcallee_txt = "%s/%s"%(gl.G_prjdata_dir,"xcallee.txt")

    def run_gremlin_query(self, query):
        return self.db_provider.run_gremlin_query(query)

    def query_loc_callsite(self, callee_id):
        query = """
                g.v(%s).statements.transform{[g.v(it.functionId).functionToFile.filepath, it.location]}
                """ % callee_id
        result = self.run_gremlin_query(query)
        loc = "%s: %s" % (result[0][0][0], result[0][1])
        return loc

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

    def query_loc_callsite(self, callee_id):
        query = """
        g.v(%s).statements.transform{[g.v(it.functionId).functionToFile.filepath, it.location]}
        """ % callee_id
        result = self.run_gremlin_query(query)
        loc = "%s: %s" % (result[0][0][0], result[0][1])
        return loc

    #result = [isVar funcname callee_counts,is_err,
    # ratio_ft_check, ratio_ft_path,ratio_ft_stmt,ratio_ft_notusedTwoside]
    def is_xCallee(self, function_name):
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
        obj_MiningErrFunc = MiningxCalleeErr(feature_callees)
        #mining_result = [callee_counts,is_err,
        # ratio_ft_check, ratio_ft_path,ratio_ft_stmt,ratio_ft_notusedTwoside]
        mining_result = obj_MiningErrFunc.run()
        # 修正返回值函数判断,若存在检查比例，显然具有返回值。其余保持原结果
        write_info(gl.G_debuginfo_path, mining_result)
        return mining_result



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
            xp_tmp = self.is_xCallee(function_name)
            xpoint_reasult.append(xp_tmp)
            num_alalysed_func = num_alalysed_func +1
            for item in xp_tmp:

                loc = self.query_loc_callsite(item[0])
                print item,loc
        return



if __name__ == '__main__':

    import datetime
    start_time = datetime.datetime.now()
    print "\nBegin time: %s \n" % start_time
    obj_MiningErrfuncShell = MiningErrfuncShell()
    obj_MiningErrfuncShell.run()
    end_time = datetime.datetime.now()
    print "\nTime Used: %s" % (end_time - start_time)


