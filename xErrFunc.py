# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract err function (return-sensitive function)
# -----------------------------

# import sys
import argparse
import datetime
from mining_err_func import MiningErrFunc
from extract_errfun_feature import ExtractErrFunFeatures
from database_provider import DBContentsProvider
from ObjDataAndBinFile import ObjDataAndBinFile

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
        allCallee_name = self.query_allCallee_name()
        for function_name in allCallee_name:
            function_name_str = function_name.encode('gbk')
            extract_errfun_feature = ExtractErrFunFeatures(function_name_str)
            #patterns = extract_check_patterns.run(False, callee_ids)
            feature_callees = extract_errfun_feature.run(flag_thread=False)

            obj_MiningErrFunc = MiningErrFunc(feature_callees)

            mining_result = obj_MiningErrFunc.run()
            print "%s: "%function_name_str
            print mining_result
        return


if __name__ == '__main__':

    import datetime
    start_time = datetime.datetime.now()
    print "\nBegin time: %s \n" % start_time
    obj_MiningErrfuncShell = MiningErrfuncShell()
    obj_MiningErrfuncShell.run()
    end_time = datetime.datetime.now()
    print "\nTime Used: %s" % (end_time - start_time)


