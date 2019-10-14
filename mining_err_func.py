# coding:utf-8
# -----------------------------
# coded by cl in 2019-01-02
# use the information entropy to measure the difference between the callee's constraint
# and the other callees' constraints, and consider these callees whose measurement are bigger than a threshold value.
# the measure progress will be calculated on every argument, and the sum of all arguments'entropy is the callee's
# entropy. the argument' entropy is the average entropy of each pairs of the target callee with other callees.
# -----------------------------

import math
from ObjDataAndBinFile import ObjDataAndBinFile
from display_data import DisplayEntropyInfo

class MiningErrFunc:

    def __init__(self, calee_featureList):
        self.calee_featureList = calee_featureList
        #关于路径数量，语句数量“明显差异”的阈值，比例 > thld_path_ratio
        tmp_test = 2
        self.thld_path_ratio = tmp_test
        self.thld_stmt_ratio = tmp_test
        #关于特征是否满足的阈值
        self.thld_is_check = 0.8
        self.thld_is_path = 0.8
        self.thld_is_stmt = 0.8
        self.thld_is_useOneside = 0.8
        #关于个性特征的权重值
        self.weight_path = 0.5
        self.weight_stmt = 0.5
        self.weight_useOneSide = 1

    # feature_callee = [    callee_id, 未使用前检查（0,1）,
    #                       [正确路径的路径数量,正确路径的语句数量，错误路径中使用返回值变量(1,0)],
    #                       [错误路径的路径数量,正确路径的语句数量，错误路径中使用了返回值变量(1,0)]
    #                   ]
    def get_featrue(self,featureList):
        ft_call = []
        for feature in featureList:
            if(feature[2][1] > feature[3][1]):
                if(feature[2][0] != 0 and feature[3][0] == 0):
                    path_ratio = 999
                if(feature[2][0] == 0 and feature[3][0] == 0):
                    path_ratio = 0

                if(feature[2][1] != 0 and feature[3][1] == 0):
                    stmt_ratio = 999
                if(feature[2][1] == 0 and feature[3][1] == 0):
                    stmt_ratio = 0

                if(feature[3][0] != 0):
                    path_ratio = round(float(feature[2][0])/feature[3][0],2)
                if(feature[3][1] != 0):
                    stmt_ratio = round(float(feature[2][1])/feature[3][1],2)
            else:
                if(feature[3][0] != 0 and feature[2][0] == 0):
                    path_ratio = 999
                if(feature[3][0] == 0 and feature[2][0] == 0):
                    path_ratio = 0

                if(feature[3][1] != 0 and feature[2][1] == 0):
                    stmt_ratio = 999
                if(feature[3][1] == 0 and feature[2][1] == 0):
                    stmt_ratio = 0
                if(feature[2][0] != 0):
                    path_ratio = round(float(feature[3][0])/feature[2][0],2)
                if(feature[2][1] != 0):
                    stmt_ratio = round(float(feature[3][1])/feature[2][1],2)
            if path_ratio >= self.thld_path_ratio:
                ft_path = 1
            else:
                ft_path = 0
            if stmt_ratio >= self.thld_stmt_ratio:
                ft_stmt = 1
            else:
                ft_stmt = 0

            if((feature[2][2] == 1 and feature[3][2] == 0) or (feature[2][2] == 0 and feature[3][2] == 1)):
                ft_used_oneside = 1
            else:
                ft_used_oneside = 0
            ft_call.append([feature[0],feature[1],ft_path,ft_stmt,ft_used_oneside])
        return ft_call

    def mining_err(self, ft_call):
        num = len(ft_call)
        count_ft_check = 0
        count_ft_path  = 0
        count_ft_stmt = 0
        count_ft_usedOneside = 0
        for ft in ft_call:
            count_ft_check = count_ft_check + ft[1]
            count_ft_path = count_ft_path + ft[2]
            count_ft_stmt = count_ft_stmt + ft[3]
            count_ft_usedOneside = count_ft_usedOneside + ft[4]
        ratio_ft_check = round(float(count_ft_check)/num,2)
        ratio_ft_path  = round(float(count_ft_path)/num,2)
        ratio_ft_stmt = round(float(count_ft_stmt)/num,2)
        ratio_ft_usedOneside = round(float(count_ft_usedOneside)/num,2)

        #挖掘策略
        weight_call = 0
        if(ratio_ft_check > self.thld_is_check):
            is_err = 1
        else:
            is_err = 0

        if(ratio_ft_path >= self.thld_is_path):
            weight_call = weight_call + self.weight_path
        if(ratio_ft_stmt >= self.thld_is_stmt):
            weight_call = weight_call + self.weight_stmt
        if(ratio_ft_usedOneside >= self.thld_is_useOneside):
            weight_call = weight_call + self.weight_useOneSide
        mining_result = [is_err, weight_call, ratio_ft_path,ratio_ft_stmt,ratio_ft_usedOneside]
        return mining_result
        #display

    def run(self):
        ft_call = self.get_featrue(self.calee_featureList)
        mining_result = self.mining_err(ft_call)
        # 打印挖掘结果
        print mining_result
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

    filename = "Data/malloc.data"
    #filename = "Data/42153.data"
    featureList = ObjDataAndBinFile.binfile2objdata(filename)
    obj_MiningErrFunc = MiningErrFunc(featureList)
    featurecallee = obj_MiningErrFunc.run()

    #d = DisplayEntropyInfo(entropy)
    #d.display_entropy()
    #print entropy
    endtime = datetime.datetime.now()
    print "\nEnd: %s"%endtime
    print "\nTime Used: %s"%(endtime - starttime)


