# coding:utf-8
# -----------------------------
# 编码作者：cl
# 更新时间：2019-12-05
# 模块功能：根据提取的特征相关信息，构建特征，根据安全特征识别返回值敏感型函数，根据辅助特征评估函数优先级。
# -----------------------------

import math
from ObjDataAndBinFile import ObjDataAndBinFile
from display_data import DisplayEntropyInfo
from database_provider import DBContentsProvider
from config import *

class MiningErrFunc:

    def __init__(self, calee_featureList):
        self.db_provider = DBContentsProvider()
        self.calee_featureList = calee_featureList
        #关于路径数量，语句数量“明显差异”的阈值，比例 > thld_path_ratio
        self.thld_path_ratio = G_thld_path_ratio
        self.thld_stmt_ratio = G_thld_stmt_ratio
        #关于特征是否满足的阈值
        self.thld_is_check = G_thld_is_check
        self.thld_is_path = G_thld_is_path
        self.thld_is_stmt = G_thld_is_stmt
        self.thld_is_notuseTwosides = G_thld_is_notuseTwosides
        #关于个性特征的权重值
        #self.weight_path = G_weight_path
        #self.weight_stmt = G_weight_stmt
        #self.weight_useOneSide = G_weight_useOneSide

    def run_gremlin_query(self, query):
        return self.db_provider.run_gremlin_query(query)

    def query_loc_callsite(self, callee_id):
        query = """
            g.v(%s).statements.transform{[g.v(it.functionId).functionToFile.filepath, it.location]}
            """ % callee_id
        result = self.run_gremlin_query(query)
        loc = "%s: %s" % (result[0][0][0], result[0][1])
        return loc
    # feature_callee = [    callee_id, 未使用前检查（0,1）,
    #                       [正确路径的路径数量,正确路径的语句数量，错误路径中使用返回值变量(1,0)],
    #                       [错误路径的路径数量,正确路径的语句数量，错误路径中使用了返回值变量(1,0)]
    #                   ]
    # 正确路径：true边的路径；错误路径：false边的路径
    def get_featrue(self,featureList):
        ft_call = []
        for feature in featureList:
            callee_id = feature[0]
            var_ischecked = feature[1]
            tpath_paths_count = feature[2][0]
            fpath_paths_count = feature[3][0]
            tpath_stmts_count = feature[2][1]
            fpath_stmts_count = feature[3][1]
            tpath_rvar_isused = feature[2][2]
            fpath_rvar_isused = feature[3][2]

            if(tpath_stmts_count > fpath_stmts_count):
                if(tpath_paths_count != 0 and fpath_paths_count == 0):
                    path_ratio = 999
                if(tpath_paths_count == 0 and fpath_paths_count == 0):
                    path_ratio = 0

                if(tpath_stmts_count != 0 and fpath_stmts_count == 0):
                    stmt_ratio = 999
                if(tpath_stmts_count == 0 and fpath_stmts_count == 0):
                    stmt_ratio = 0

                if(fpath_paths_count != 0):
                    path_ratio = round(float(tpath_paths_count)/fpath_paths_count,2)
                if(fpath_stmts_count != 0):
                    stmt_ratio = round(float(tpath_stmts_count)/fpath_stmts_count,2)
            else:
                if(fpath_paths_count != 0 and tpath_paths_count == 0):
                    path_ratio = 999
                if(fpath_paths_count == 0 and tpath_paths_count == 0):
                    path_ratio = 0

                if(fpath_stmts_count != 0 and tpath_stmts_count == 0):
                    stmt_ratio = 999
                if(fpath_stmts_count == 0 and tpath_stmts_count == 0):
                    stmt_ratio = 0
                if(tpath_paths_count != 0):
                    path_ratio = round(float(fpath_paths_count)/tpath_paths_count,2)
                if(tpath_stmts_count != 0):
                    stmt_ratio = round(float(fpath_stmts_count)/tpath_stmts_count,2)
            if path_ratio >= self.thld_path_ratio:
                ft_path = 1
            else:
                ft_path = 0
            if stmt_ratio >= self.thld_stmt_ratio:
                ft_stmt = 1
            else:
                ft_stmt = 0

            if tpath_rvar_isused == 1 and fpath_rvar_isused == 1:
                ft_used_oneside = 0
            else:
                ft_used_oneside = 1
            ft_call.append([callee_id,var_ischecked,ft_path,ft_stmt,ft_used_oneside])
        return ft_call

    def mining_err(self, ft_call):
        callee_counts = len(ft_call)
        count_ft_check = 0
        count_ft_path  = 0
        count_ft_stmt = 0
        count_ft_notusedTwoside = 0
        for ft in ft_call:
            count_ft_check = count_ft_check + ft[1]
            count_ft_path = count_ft_path + ft[2]
            count_ft_stmt = count_ft_stmt + ft[3]
            count_ft_notusedTwoside = count_ft_notusedTwoside + ft[4]
        ratio_ft_check = round(float(count_ft_check)/callee_counts,2)
        ratio_ft_path  = round(float(count_ft_path)/callee_counts,2)
        ratio_ft_stmt = round(float(count_ft_stmt)/callee_counts,2)
        ratio_ft_notusedTwoside = round(float(count_ft_notusedTwoside)/callee_counts,2)

        #挖掘策略
        weight_call = 0
        if((ratio_ft_check > self.thld_is_check) and
                (ratio_ft_path > self.thld_is_path) and
                (ratio_ft_stmt > self.thld_is_stmt) and
                (ratio_ft_notusedTwoside > self.thld_is_notuseTwosides)):
            is_err = 1
        else:
            is_err = 0

        # 此处不再优先级评估
        """
        if(ratio_ft_path >= self.thld_is_path):
            weight_call = weight_call + self.weight_path
        if(ratio_ft_stmt >= self.thld_is_stmt):
            weight_call = weight_call + self.weight_stmt
        if(ratio_ft_notusedTwoside >= self.thld_is_notuseTwosides):
            weight_call = weight_call + self.weight_useOneSide
        """
        mining_result = [callee_counts, is_err, ratio_ft_check, ratio_ft_path,ratio_ft_stmt,ratio_ft_notusedTwoside]
        return mining_result
        #display

    def run(self):
        ft_call = self.get_featrue(self.calee_featureList)
        mining_result = self.mining_err(ft_call)
        # 打印挖掘结果
        f = open("Data/result.txt","w")
        print >> f, "ft_call = "
        print >> f,mining_result
        for i in range(0,len(ft_call)):
            loc = self.query_loc_callsite(self.calee_featureList[i][0])
            print >> f, "%s:"%(loc)
            print loc
            print >> f,self.calee_featureList[i]
            print self.calee_featureList[i]
            print >> f,ft_call[i]

        return mining_result

    """
    def run(self, function_name):
        cstr_lib = CnvCstrLib().cnv_checkdata(function_name)
        abnor_callees = self.find_abnor_callee(self.cstr_lib)
        return abnor_callees
    """
    # Todo: query_pased_control is often failed.


if __name__ == '__main__':

    import datetime

    starttime = datetime.datetime.now()
    print "\nBegin time: %s"%starttime
    """
    print MiningErrFunc.calculate_entropy([0.6, 0.4], 4)
    print MiningErrFunc.calculate_entropy([0.6], 4)
    print MiningErrFunc.calculate_entropy([0.4], 4)

    print MiningErrFunc.calculate_entropy([1], 2)
    """

    filename = "Data/alloc_workqueue.data"
    #filename = "Data/42153.data"
    featureList,flag_rvar_func = ObjDataAndBinFile.binfile2objdata(filename)
    obj_MiningErrFunc = MiningErrFunc(featureList)
    featurecallee = obj_MiningErrFunc.run()

    #d = DisplayEntropyInfo(entropy)
    #d.display_entropy()
    #print entropy
    endtime = datetime.datetime.now()
    print "\nEnd: %s"%endtime
    print "\nTime Used: %s"%(endtime - starttime)


