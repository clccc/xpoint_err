# coding:utf-8
# -----------------------------
# 编码作者：cl
# 更新时间：2019-12-05
# 模块功能：提取某函数各个调用实例的安全特征和辅助特征的相关信息
# 输入：函数名，或者实例id列表
# 输出：特征信息feature_callee
# feature_callee = [    callee_id, 未使用前检查（0,1）,
#                       [正确路径的路径数量,正确路径的语句数量，正确路径中使用返回值变量(1,0)],
#                       [错误路径的路径数量,错误路径的语句数量，错误路径中使用了返回值变量(1,0)]
#                   ]
# -----------------------------

from threading import Thread
from database_provider import DBContentsProvider
from ObjDataAndBinFile import ObjDataAndBinFile

class ExtractErrFunFeatures:
    def __init__(self, function_name):
        self.db_provider = DBContentsProvider()
        self.file_io_provider = ObjDataAndBinFile()
        self.function_name = function_name
        self.count_threads = 20

    def run_gremlin_query(self, query):
        return self.db_provider.run_gremlin_query(query)

    def save_data_to_file(self, data, file_path):
        # filename = "Data/OutStatsData_%s.data"%time.strftime('%Y%m%d-%H%M%S')
        # print "生成GetOutStatsData的原始数据文件:%s" % file_path
        self.file_io_provider.objdata2file(data, file_path)

    def query_loc_callsite(self, callee_id):
        query = """
            g.v(%s).statements.transform{[g.v(it.functionId).functionToFile.filepath, it.location]}
            """ % callee_id
        result = self.run_gremlin_query(query)
        loc = "%s: %s" % (result[0][0][0], result[0][1])
        return loc

    def query_callee_ids(self, function_name):
        query = """
        g.V().has('type','Callee').has('code','%s').id.toList()
        """ % function_name
        callee_ids = self.run_gremlin_query(query)
        return callee_ids

    def query_callsite_id(self, callee_id):
        query = """
        g.v(%s).in.in.id
        """ % callee_id
        callsite_id = self.run_gremlin_query(query)
        return callsite_id[0]

    def query_backward_paths(self, callee_id):
        query = """
        getBackwardPaths(%s)
        """ % callee_id
        all_paths = self.run_gremlin_query(query)
        return all_paths

    def query_farward_paths_from_condition(self, condition_id):
        query = """
        getFarwardPaths_from_condition(%s)
        """ % condition_id
        all_paths = self.run_gremlin_query(query)
        return all_paths

    # def_chain = src.id <--var_str-- dst.id
    def query_define_chains(self, path):
        def_chain = []
        for node_id in path:
            query = """
            g.v(%s).inE('REACHES').transform{[it.inV.id, it.var, it.outV.id]}
            """ % node_id
            def_chain_tmp = self.run_gremlin_query(query)
            # select the definition of the @path
            for chain in def_chain_tmp:
                if (chain[0][0] in path) and (chain[2][0] in path):
                    # remove the define node which dst == src, it will make some process loop forever
                    if chain[0][0] != chain[2][0]:
                        def_chain.append([chain[0][0], chain[1], chain[2][0]])

        # remove the invalid define chain from @def_chain
        invalid_chains = []
        for i in range(0, len(def_chain)):
            for j in range(0, len(def_chain)):
                if i == j:
                    continue
                # the nearest definition on the same node with the same variable is the valid one
                if def_chain[i][0] == def_chain[j][0] and def_chain[i][1] == def_chain[j][1]:
                    if path.index(def_chain[i][2]) > path.index(def_chain[j][2]):
                        invalid_chains.append(i)
                    else:
                        invalid_chains.append(j)
        invalid_chains = self.unique_list(invalid_chains)
        invalid_chains.sort(reverse=True)
        for i in invalid_chains:
            def_chain.remove(def_chain[i])
        return def_chain

    def query_symbols_by_ids(self, ids):
        symbols_id = []
        symbols_code = []
        for arg in ids:
            query = """
            _getSymbols(%s)
            """ % arg
            s_ids = self.run_gremlin_query(query)
            symbols_id.append(s_ids)
            s_codes = []
            if s_ids:
                for vid in s_ids:
                    s_codes.append(self.query_code_by_id(vid))
            else:
                s_codes.append(u'')
            symbols_code.append(s_codes)
        return symbols_id, symbols_code

    def query_define_vars_dst_on_symbols(self, src_id, symbols, def_chain):
        define_vars = []
        define_dst_node = []
        callsite = src_id
        for s in symbols:
            var_symbol = self.query_code_by_id(s)
            head_node = self.search_dst_by_var_src(callsite, var_symbol, def_chain)
            if not head_node:
                continue
            define_vars.append(var_symbol)
            define_dst_node.append(head_node)
            src_nodes = [head_node]
            while src_nodes:
                src_new = []
                for src in src_nodes:
                    middle_define_vars, dst_nodes = self.search_vars_dsts_by_src(src, def_chain)
                    if middle_define_vars:
                        for dst in dst_nodes:
                            if dst not in define_dst_node:
                                src_new.extend(dst_nodes)

                            define_vars.extend(middle_define_vars)
                            define_dst_node.extend(dst_nodes)

                src_nodes = src_new
            #define_dst_node = self.unique_list(define_dst_node)
            #define_vars = self.unique_list(define_vars)
        return define_vars, define_dst_node

    def query_code_by_id(self, vid):
        query = """
        _getCodeById(%s)
        """ % vid
        code = self.run_gremlin_query(query)
        return code

    # search dst node from def_chain by var and src node
    def search_dst_by_var_src(self, src, var, def_chain):
        for def_node in def_chain:
            if src == def_node[0] and var == def_node[1]:
                return def_node[2]
        return False

    def search_vars_dsts_by_src(self, src, def_chain):
        define_vars = []
        dst_nodes = []
        for def_node in def_chain:
            if def_node[0] == src:
                define_vars.append(def_node[1])
                dst_nodes.append(def_node[2])
        return define_vars, dst_nodes

    def query_flowlabel_between_nodes(self, out_v, in_v):
        query = """
        _getFlowlabelOfCfgIds(%s, %s)
        """ % (out_v, in_v)
        flowlabel = self.run_gremlin_query(query)
        return flowlabel

    # parseControl return [flowlabel_code, ids_child[0], tpye_code, operator_code, children]
    # children = [id,type,code]
    def query_parsed_control(self, control_id, next_node):
        query = """
        parseControl(%s,%s)
        """ % (control_id, next_node)
        control_info = self.run_gremlin_query(query)

        flowlabel_code = control_info[0]
        id_exp = control_info[1]
        type_exp = control_info[2]
        operator_expr = control_info[3]
        children_expr = control_info[4]

        return flowlabel_code, id_exp, type_exp, operator_expr, children_expr

    # the controls are condition statements control the callsite_id
    def query_controls(self, callsite_id):
        query = """4849840
        getControlsFromCfgId(%s)
        """ % callsite_id
        controls = self.run_gremlin_query(query)
        return controls

    # get controls of the path
    def query_controls_path(self, controls, path):
        controls_path = []
        for c in controls:
            if c in path:
                controls_path.append(c)
        return controls_path

    def query_control_symbols(self, control):
        query = """
        _getSymbols(%s)
        """ % control
        control_symbols = self.run_gremlin_query(query)
        return control_symbols

    @staticmethod
    def unique_list(old_list):
        new_list = []
        for i in old_list:
            if i not in new_list:
                new_list.append(i)
        return new_list

    @staticmethod
    def is_lists_cross(list1, list2):
        for l in list1:
            if l in list2:
                return True
        return False

    @staticmethod
    def get_index_same_items_of_list1(list1, list2):
        indexList = []
        for i in range(0,len(list1)):
            if list1[i] in list2:
                indexList.append(i)
        return indexList

    @staticmethod
    def list1_VSset_list2(list1,list2):
        if (not list1) or (not list2):
            return "xx"
        if set(list1) > set(list2):
            return '>'
        if set(list1) == set(list2):
            return '='
        if set(list1) < set(list2):
            return '<'
        else:
            return 'x'

    # 返回returnVar_code 或者 false
    def query_returnVar_of_callsite(self, callee_id):
        query = """
        _getReturnVarOfCalleeId(%s)
        """ % (callee_id)
        returnVar = self.run_gremlin_query(query)
        return returnVar

    # 先判断当前位置是否为条件检查，是则返回当前节点，否则继续沿着CFG图继续搜索，返回checkpoint_id_of_var或者false
    def query_checkpoint_of_returnVar(self, callee_id, var):
        query = """
        _query_checkpoint_of_returnVar(%s,'%s')
        """ % (callee_id,var)
        #query = """
        #_getCheckPointOfCalleeId(%s,"%s")
        #""" % (callee_id, var)
        checkpoint = self.run_gremlin_query(query)
        return checkpoint

    def is_a_isparent_b(self, nodeid, var):
        query = """
        is_a_isparent_b(%s,'%s')
        """ % (nodeid,var)
        result = self.run_gremlin_query(query)
        return result

    def run_thread(self, callee_ids):
        print "错误：本程序的多线程版本尚未实现"
        return False

    # feature_callee = [    callee_id, 未使用前检查（0,1）,
    #                       [正确路径的路径数量,正确路径的语句数量，正确路径中使用返回值变量(1,0)],
    #                       [错误路径的路径数量,正确路径的语句数量，错误路径中使用了返回值变量(1,0)]
    #                   ]
    def run_no_thread(self, callee_ids):
        feature_func = []
        feature_callee = []
        i = 0
        # -test
        print "len(callee_ids) = %d " % (len(callee_ids))
        # -test
        for callee_id in callee_ids:
            feature_callee = [callee_id, 0, [0,0,0],[0,0,0]]
            #implicit_check_patterns = [[] for i in range(arg_num)]
            #explicit_check_patterns = [[] for i in range(arg_num)]
            #check_patterns_callee = [implicit_check_patterns, explicit_check_patterns]
            i = i+1
            # get callsite_id = cfgnodid of callee_id
            callsite_id = self.query_callsite_id(callee_id)
            # -test
            print "%3d.%10d%10d "%(i, callee_id, callsite_id)
            # -test

            # get controls control the callsite_id
            #all_controls = self.query_controls(callsite_id)
            #两种检查方式：1是检查返回值变量，2是函数在检查语句的表达式中直接检查
            # 1. 提取返回值变量
            returnVar = self.query_returnVar_of_callsite(callee_id)
            #print "%s : \t %s" %(self.query_loc_callsite(callee_id),returnVar)
            # 2. 提取未使用前参加的第一个条件检查语句id
            if not returnVar:
                var_code = "Err"
            else:
            # 遇到b->buf类似的例子时候，会返回多个变量。此仅仅考虑了第一个symbol
            # b->buf，会分为b，bug两个变量，需后续改进
                if isinstance(returnVar, list):
                    var_code = returnVar[0]
                else:
                    var_code = returnVar
            checkpoint_id = 0
            checkpoint_id = self.query_checkpoint_of_returnVar(callee_id,var_code)
            print "%s : \t %s %s" %(self.query_loc_callsite(callee_id),checkpoint_id,returnVar)
            if not checkpoint_id:
                feature_callee = [callee_id, 0, [0,0,0],[0,0,0]]
                feature_func.append(feature_callee)
                continue
            #
            #if(returnVar == False) and (checkpoint_id == False)):

            # 3. 存在未使用检查，继续分析路径信息
            feature_callee = [callee_id, 1]
            all_paths = self.query_farward_paths_from_condition(checkpoint_id)
            #todo: switch未处理，导致all_paths =  false
            if not all_paths:
                feature_callee = [callee_id, 1, [0,0,0],[0,0,0]]
                feature_func.append(feature_callee)
                continue

            print all_paths
            for path in all_paths:
                feature_right_path = [0,0,0]
                if path:
                    num_lpaths = len(path)
                    num_lstatements = sum(len(lpath) for lpath in path)
                    for childpath in path:
                        flag_returnVar_used = self.is_var_usedin_path(childpath, var_code)
                        if flag_returnVar_used:
                            break
                    feature_right_path = [num_lpaths, num_lstatements, flag_returnVar_used]
                feature_callee.append(feature_right_path)
            feature_func.append(feature_callee)
        return feature_func

    def is_var_usedin_path(self, lpath, returnVar):
        flag_returnVar_used = 0
        if(returnVar == "Err"):
            return 0
        for smt_id in lpath:
            if self.is_a_isparent_b(smt_id, returnVar):
                flag_returnVar_used = 1
                break
            else:
                flag_returnVar_used = 0
        return flag_returnVar_used

    def run(self, flag_thread=False, *callee_from):
        if len(callee_from):
            if isinstance(callee_from[0], list):
                callee_ids = callee_from[0]
                filepath = "Data/%s.data" % callee_ids[0]
        else:
            callee_ids = self.query_callee_ids(self.function_name)
            filepath = "Data/%s.data" % self.function_name

        if flag_thread:
            feature_func = self.run_thread(callee_ids)
        else:
            feature_func = self.run_no_thread(callee_ids)

        print "feature_func =： "
        #print check_patterns
        # display chek_patterns
        for pattern in feature_func:
            loc = self.query_loc_callsite(pattern[0])
            print "%s:" % (loc)
            print pattern

        ObjDataAndBinFile.objdata2file(feature_func, filepath)
        return feature_func


if __name__ == '__main__':
    import datetime

    start_time = datetime.datetime.now()
    print "\nBegin time: %s \n" % start_time
    #callee_ids = [637251]
    #callee_ids = [73439]
    #callee_ids = [23648]
    #function_name = "BUF_strlcat"
    #function_name = "pread"
    #function_name = "magic_error"
    #function_name = "file_regcomp"
    #function_name ="snpri
    #function_name ="magic_compile"
    #function_name ="parse"
    #function_name = "alloc_workqueue"
    extract_errfun_feature = ExtractErrFunFeatures(function_name)
    #patterns = extract_check_patterns.run(False, callee_ids)
    patterns = extract_errfun_feature.run(flag_thread=False)

    """
    flowlabel_code, operate_code, children = \
        extract_check_patterns.query_parsed_control(6638, 6651)
    """

    end_time = datetime.datetime.now()
    print "\nTime Used: %s (%s ~ %s)" % ((end_time - start_time), start_time, end_time)
