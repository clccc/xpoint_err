# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract err function (return-sensitive function)
# -----------------------------

# import sys
import os
import argparse
import datetime
from mining_err_func import MiningErrFunc
from extract_errfun_feature import ExtractErrFunFeatures
from database_provider import DBContentsProvider
from ObjDataAndBinFile import ObjDataAndBinFile
import datetime

# sys.path.append("..")


class MiningErrfuncShell:

    def __init__(self):
        self.db_provider = DBContentsProvider()
        parser = argparse.ArgumentParser(description='Find defect callees.')
        parser.add_argument('--function', '-func',
                            help='the target argument-sensitive function name')
        parser.add_argument("-f", "--filepath",
                            help=' file of check information saved')
        parser.add_argument("-t", "--threshold", required=False, type=int, default=0.5,
                            help="the threshold of the entropy")
        self.args_ = parser.parse_args()

    def run_gremlin_query(self, query):
        return self.db_provider.run_gremlin_query(query)

    def query_allCallee_name(self):
        query = """
            g.V.has('type','Callee').as('x').code.dedup().back('x').code.toList()
            """
        result = self.run_gremlin_query(query)
        return result

    def run(self):
        #一些奇怪的，暂时无法消除bug（与joern实现有关）的函数，略过
        func_unnormal = ['INCOHERENT']
        allCallee_name = self.query_allCallee_name()
        display_data = []
        num_func = len(allCallee_name)
        num_alalysed_func = 0
        f_debug= open("Data/degbug.txt",'a' )
        f_debug.write("\nBeginTime = %s   num_func = %s\n"%(datetime.datetime.now(),num_func))
        f_debug.close
        for function_name in allCallee_name:
            if function_name in func_unnormal:
                continue
            function_name_str = function_name.encode('gbk')
            #
            datapath = "Data/result_libtif407/%s.data"%function_name_str
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
            display_data.append(tmp)
            num_alalysed_func = num_alalysed_func +1
            f_debug= open("Data/degbug.txt",'a' )
            f_debug.write(str(tmp[1]) + str("  ") + str(tmp[2]) + "  " +  str(tmp[0])
                            + "  " +  str(tmp[3])+ "  " +  str(tmp[4])+ " "  + str(tmp[5]))
            f_debug.write("\n")
            f_debug.close()
        f_debug= open("Data/degbug.txt",'a' )
        f_debug.write("EndTime = %s   num_alalysed_func = %s\n"%(datetime.datetime.now(),num_alalysed_func))
        f_debug.close()

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


