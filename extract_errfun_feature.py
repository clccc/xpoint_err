# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract raw explict-check and implicit-check of every callee, which is call instance of
# the argument-sensitive function @function_name interested
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

    def set_implicit_check_pattern(self, arg_checked, arg_by):
        # CNT is constant, OutVar is variable from outside of caller
        if arg_by == "CNT":
            return "arg_%s DEFBY %s" % (arg_checked, arg_by)
        if arg_by == "OutVar":
            return "arg_%s DEFBY %s" % (arg_checked, arg_by)
        return "arg_%s DEFBY arg_%s" % (arg_checked, arg_by)
    '''
    def set_explicit_check_pattern(self, arg_checked, checkinfo):

        flowlabel_code = checkinfo[0][0]
        operator_code = checkinfo[1]
        related_args = checkinfo[2]
        pattern_str = "%s %s arg_%s VS (" % (arg_checked, flowlabel_code, operator_code)
        for arg_index in related_args:
            pattern_str += " arg_%s " % arg_index
        pattern_str += ")"
        return
    '''

    def set_explicit_check_pattern(self, arg_checked, checkinfo):
        # explicit_checkinfo_args[index_arg].append([norm_cmp_items, norm_cmp_op, norm_cmp_value])
        norm_cmp_items = "f("
        for i in range(0, len(checkinfo[0])-1):
            norm_cmp_items += "arg_%d, " % checkinfo[0][i]
        norm_cmp_items += "arg_%d)" % checkinfo[0][len(checkinfo[0])-1]

        norm_cmp_op = checkinfo[1]

        norm_cmp_value = "f("
        for i in range(0, len(checkinfo[2]) - 1):
            norm_cmp_value += "%s, " % checkinfo[2][i]
        norm_cmp_value += "%s)" % checkinfo[2][len(checkinfo[2])-1]

        return "%s %s %s" % (norm_cmp_items, norm_cmp_op, norm_cmp_value)

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

    def query_args(self, callee_id):
        query = """
        getArgs(%s)
        """ % callee_id
        arg_ids = self.run_gremlin_query(query)
        return arg_ids

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

    def query_check_patterns_path(self, callee_id, callsite_id, path, controls_path):
        arg_ids = self.query_args(callee_id)
        symbols_id_of_args, symbols_code_of_args = self.query_symbols_by_ids(arg_ids)
        def_chain_path = self.query_define_chains(path)
        define_vars_of_args = []
        define_dst_of_args = []
        for symbols_arg in symbols_id_of_args:
            defvars_of_arg, define_dst_of_arg = \
                self.query_define_vars_dst_on_symbols(callsite_id, symbols_arg, def_chain_path)
            define_vars_of_args.append(defvars_of_arg)
            define_dst_of_args.append(define_dst_of_arg)

        arg_num = len(arg_ids)

        # I. 隐式约束 query_implicit_check_patterns_path
        implicit_check_patterns = [[] for i in range(arg_num)]

        for i in range(0, arg_num):
            # 1. 判断该参数是否为常量
            #   1.1 没有用到符号
            if not symbols_id_of_args[i]:
                implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, "CNT"))
                continue

            # Because Joern can not identify the Global variable/const,
            # the arg may have symbol but its define_vars_of_args is NULL.
            # Because the global variable is not recommend, used rarely,
            # so we set its check pattern as defined by const  "CNT"
            # const: type 'PrimaryExpression'
            #   1.2 有符号没却没有用于定义的变量 and 符号代码全为大写字符，则判断为全局变量，Joern不精准的原因
            if symbols_id_of_args[i] and (not define_vars_of_args[i]):
                flag_notupper = False
                for symbol in symbols_code_of_args[i]:
                    if not symbol.isupper():
                        flag_notupper = True
                        break
                if not flag_notupper:
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, "CNT"))
                    continue

            # If the right values of all the define nodes of the define chains' tails (define_dst_of_args[i]) are constants,
            # the arg is defined by constant
            #   1.3. 所有的定义语句都是常量赋值，那么最终的实参也是常量
            flag_value = True
            if define_dst_of_args[i]:
                for nodeid in define_dst_of_args[i]:
                    nodecode = self.run_gremlin_query("g.v(%s).code" % nodeid)
                    value = nodecode.split("=", 1)
                    if len(value) != 2:
                        flag_value = False
                        break
                    rightvalue = value[1]
                    # 此处有错误，如果是字符串常量呢？
                    if rightvalue.isdigit() != True:
                        flag_value = False
                        break
                if flag_value:
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, "CNT"))
                    continue
            for j in range(i + 1, arg_num):
                # 2. 判断与其它参数的关系
                #   2.1. symbols属于包含关系
                if self.list1_VSset_list2(symbols_id_of_args[i], symbols_id_of_args[j]) == '>':
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, j))
                    continue
                #if self.is_lists_cross(symbols_id_of_args[i], symbols_id_of_args[j]):
                #    implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, j))
                if self.list1_VSset_list2(symbols_id_of_args[i], symbols_id_of_args[j]) == '<':
                    implicit_check_patterns[j].append(self.set_implicit_check_pattern(j, i))
                    continue
                if self.list1_VSset_list2(symbols_id_of_args[i], symbols_id_of_args[j]) == '=':
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, j))
                    implicit_check_patterns[j].append(self.set_implicit_check_pattern(j, i))
                    continue

                #   2.2. var包含关系
                if self.list1_VSset_list2(define_vars_of_args[i], symbols_code_of_args[j]) == '>':
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, j))
                    continue
                if self.list1_VSset_list2(define_vars_of_args[j], symbols_code_of_args[i]) == '>':
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(j, i))
                    continue

                tmp_defvar_i = define_vars_of_args[i][1:len(define_vars_of_args[i])]
                tmp_defvar_j = define_vars_of_args[j][1:len(define_vars_of_args[j])]
                if tmp_defvar_j:
                    if self.list1_VSset_list2(define_vars_of_args[i], tmp_defvar_j) == '>':
                        implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, j))
                        continue
                if tmp_defvar_i:
                    if self.list1_VSset_list2(define_vars_of_args[j], tmp_defvar_i) == '>':
                        implicit_check_patterns[i].append(self.set_implicit_check_pattern(j, i))
                        continue
                if tmp_defvar_i and tmp_defvar_j:
                    if self.list1_VSset_list2(tmp_defvar_j, tmp_defvar_i) == '=':
                        implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, j))
                        implicit_check_patterns[i].append(self.set_implicit_check_pattern(j, i))
                        continue

                #   2.3. 混合定义的情况
                if self.is_lists_cross(define_vars_of_args[i], define_vars_of_args[j]):
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, j))
                    implicit_check_patterns[i].append(self.set_implicit_check_pattern(j, i))
                    # implicit_check_patterns[j].append(self.set_implicit_check_pattern(j, i))
                    continue

                # 3. 其它归为未知变量：后续过程间分析时需要区分是否依赖于调用者的入参
                # the default define patten is defined by "OutVar"

                # implicit_check_patterns[i].append(self.set_implicit_check_pattern(i, "OutVar"))


        # II. 显式约束 query_explicit_check_patterns_path:
        # If there is a define node on one symbol of the @arg, whose location is between the control node @control
        # and the callsite, then the @control is not take an explicit check on the @arg.
        # Else if the defvar(@control) ^ defvar(@arg) != [], then @control is take an explicit check on the @arg.
        explicit_check_patterns = [[] for i in range(arg_num)]
        explicit_checkinfo_args = [[] for i in range(arg_num)]
        checked_arg_control = []
        symbols_id_of_controls, symbols_code_of_controls = self.query_symbols_by_ids(controls_path)
        '''
        define_vars_of_controls = []
        define_dst_of_controls = []
        for symbols_control in symbols_id_of_controls:
            defvars_of_control, define_dst_of_control = \
                self.query_define_vars_dst_on_symbols(callsite_id, symbols_control, def_chain_path)
            define_vars_of_controls.append(defvars_of_control)
            define_dst_of_controls.append(define_dst_of_control)
        '''
        # 1. 筛选有效的条件检查，并与对应的参数关联
        for index_arg in range(0, arg_num):
            for index_control in range(0, len(controls_path)):
                checked_var_of_args = self.get_index_same_items_of_list1(define_vars_of_args[index_arg],
                                                                         symbols_code_of_controls[index_control])
                location_control = path.index(controls_path[index_control])
                if checked_var_of_args:
                    flag_valid_control = True
                    for index_checked_var_of_args in checked_var_of_args:
                        location_checked_dst_node = path.index(define_dst_of_args[index_arg][index_checked_var_of_args])
                        # if one control check on var, but the var was defined again after the control,
                        # then the control is not consided as a valid check on var
                        if location_control > location_checked_dst_node:
                            flag_valid_control = False
                            break
                    if flag_valid_control:
                        # log the relation between arg and valid controls
                        checked_arg_control.append([index_arg, index_control])

        # 2.解析有效的条件检查；收集条件检查的 逻辑运算符号，结果满足条件（True，False），相关参数
        # collect check info from @checked_arg_control into each arg
        for c_arg_control in checked_arg_control:
            index_arg = c_arg_control[0]
            index_control = c_arg_control[1]

            args_by_control = []
            for tmp_arg_control in checked_arg_control:
                if tmp_arg_control[1] == index_control:
                    if tmp_arg_control[0] != index_arg:
                        args_by_control.append(tmp_arg_control[0])
            args_by_control = self.unique_list(args_by_control)
            args_by_control.sort()

            # [flowlabel_code, ids_child[0], tpye_code, operator_code, children]
            # children = [id,type,code]
            index_next_node = path.index(controls_path[index_control]) - 1
            flowlabel_code, id_exp, type_exp, operator_expr, children_expr = \
                self.query_parsed_control(controls_path[index_control], path[index_next_node])
            norm_cmp_items = []
            norm_cmp_op = ""
            norm_cmp_value = []

            if type_exp == "Identifier":
                if flowlabel_code == "True":
                    norm_cmp_value.append("notNULL")
                    norm_cmp_op = "=="
                else:
                    norm_cmp_value.append("NULL")
                    norm_cmp_op = "=="
                norm_cmp_items = [index_arg]
                explicit_checkinfo_args[index_arg].append([norm_cmp_items,norm_cmp_op,norm_cmp_value])
                continue
            # op = !
            elif type_exp == "UnaryOp":
                if flowlabel_code == "True":
                    norm_cmp_value.append("NULL")
                else:
                    norm_cmp_value.append("notNULL")
                norm_cmp_op = "=="
                norm_cmp_items = [index_arg]
                explicit_checkinfo_args[index_arg].append([norm_cmp_items, norm_cmp_op, norm_cmp_value])
                continue

            elif type_exp == "EqualityExpression":
                if flowlabel_code == "True":
                    norm_cmp_op = operator_expr
                else:
                    if operator_expr == "==":
                        norm_cmp_op = "!="
                    else:
                        norm_cmp_op = "=="
                norm_cmp_items, norm_cmp_value = self.analysis_EqualityExpression(
                    args_by_control, define_vars_of_args,index_arg, children_expr)
                explicit_checkinfo_args[index_arg].append([norm_cmp_items, norm_cmp_op, norm_cmp_value])

            elif type_exp == "RelationalExpression":
                norm_cmp_items, norm_cmp_value, flag_left_value = self.analysis_RelationalExpression(
                    args_by_control, define_vars_of_args, index_arg, children_expr)
                if flag_left_value:
                    if flowlabel_code == "True":
                        norm_cmp_op = operator_expr
                    else:
                        if operator_expr == ">": norm_cmp_op = "<"
                        elif operator_expr == ">=": norm_cmp_op = "<="
                        elif operator_expr == "<": norm_cmp_op = ">"
                        elif operator_expr == "<=": norm_cmp_op = ">="
                        else:
                            norm_cmp_op = "unknow %s" % operator_expr
                if not flag_left_value:
                    if flowlabel_code == "False":
                        norm_cmp_op = operator_expr
                    else:
                        if operator_expr == ">":
                            norm_cmp_op = "<"
                        elif operator_expr == ">=":
                            norm_cmp_op = "<="
                        elif operator_expr == "<":
                            norm_cmp_op = ">"
                        elif operator_expr == "<=":
                            norm_cmp_op = ">="
                        else:
                            norm_cmp_op = "unknow %s" % operator_expr
                explicit_checkinfo_args[index_arg].append([norm_cmp_items, norm_cmp_op, norm_cmp_value])
                continue

            else:
                print "error:unknown type of expression: %s" % type_exp


        for index_arg in range(0, arg_num):
            for checkinfo in explicit_checkinfo_args[index_arg]:
                if not checkinfo[2]:
                    print "error:explicit_checkinfo_args"
                explicit_check_patterns[index_arg].append(
                    self.set_explicit_check_pattern(arg_checked=index_arg, checkinfo=checkinfo))

        # 去重
        for i in range(0, len(implicit_check_patterns)):
            implicit_check_patterns[i] = self.unique_list(implicit_check_patterns[i])
        for i in range(0, len(explicit_check_patterns)):
            explicit_check_patterns[i] = self.unique_list(explicit_check_patterns[i])

        return implicit_check_patterns, explicit_check_patterns

    def analysis_EqualityExpression(self, args_by_control, define_vars_of_args, index_arg, children_expr):
        norm_cmp_items = []
        norm_cmp_value = []

        # child = [id, type, code]
        flag_xchild_find = False
        xchild_id = -1
        for i in range(0, len(children_expr)):
            child = children_expr[i]
            # find which child contains the vars of the checked arg
            if not flag_xchild_find:
                for symbol in define_vars_of_args[index_arg]:
                    if symbol in child[2]:
                        flag_xchild_find = True
                        xchild_id = child[0]
                        norm_cmp_items.append(index_arg)
                        break
            # 判断该index_arg相关的child是否包括那些参数的符号变量，放入norm_cmp_items
            if child[0] == xchild_id:
                for relate_arg in args_by_control:
                    for symbol_rarg in define_vars_of_args[relate_arg]:
                        if symbol_rarg in child[2]:
                            norm_cmp_items.append(relate_arg)
                            break

            # 判断该非index_arg相关的child是否包括那些参数的符号变量，放入norm_cmp_value
            if child[0] != xchild_id:
                r_args = []
                for symbol in define_vars_of_args[index_arg]:
                    if symbol in child[2]:
                        r_args.append(index_arg)
                        #norm_cmp_value.append("arg_%d" % index_arg)
                        break
                for relate_arg in args_by_control:
                    for symbol_rarg in define_vars_of_args[relate_arg]:
                        if symbol_rarg in child[2]:
                            r_args.append(relate_arg)
                            #norm_cmp_value.append("arg_%d" % relate_arg)
                            break
                tmp_r_args = self.unique_list(r_args)
                tmp_r_args.sort()
                for tmp_arg in tmp_r_args:
                    norm_cmp_value.append("arg_%d" % tmp_arg)

                if len(r_args) == 0:
                    # Because the Joern consides "NULL" as a Identifier, so it requires special handling.
                    if child[2] == "NULL":
                        norm_cmp_value.append("NULL")
                    elif child[1] == "PrimaryExpression":
                        norm_cmp_value.append(child[2])
                    else:
                        norm_cmp_value.append("Var")
                        continue

        return self.unique_list(norm_cmp_items), norm_cmp_value

    def analysis_RelationalExpression(self, args_by_control, define_vars_of_args, index_arg, children_expr):
        norm_cmp_items = []
        norm_cmp_value = []

        # child = [id, type, code]
        flag_xchild_find = False
        xchild_id = -1
        for i in range(0, len(children_expr)):
            child = children_expr[i]
            # find which child contains the vars of the checked arg
            if not flag_xchild_find:
                for symbol in define_vars_of_args[index_arg]:
                    if symbol in child[2]:
                        flag_xchild_find = True
                        xchild_id = child[0]
                        norm_cmp_items.append(index_arg)
                        break
            # 判断该index_arg相关的child是否包括那些参数的符号变量，放入norm_cmp_items
            if child[0] == xchild_id:
                for relate_arg in args_by_control:
                    for symbol_rarg in define_vars_of_args[relate_arg]:
                        if symbol_rarg in child[2]:
                            norm_cmp_items.append(relate_arg)
                            break

            # 判断该非index_arg相关的child是否包括那些参数的符号变量，放入norm_cmp_value
            if child[0] != xchild_id:
                r_args = []
                for symbol in define_vars_of_args[index_arg]:
                    if symbol in child[2]:
                        r_args.append(index_arg)
                        # norm_cmp_value.append("arg_%d" % index_arg)
                        break
                for relate_arg in args_by_control:
                    for symbol_rarg in define_vars_of_args[relate_arg]:
                        if symbol_rarg in child[2]:
                            r_args.append(relate_arg)
                            # norm_cmp_value.append("arg_%d" % relate_arg)
                            break
                tmp_r_args = self.unique_list(r_args)
                tmp_r_args.sort()
                for tmp_arg in tmp_r_args:
                    norm_cmp_value.append("arg_%d" % tmp_arg)

                if len(r_args) == 0:
                    # Because the Joern consides "NULL" as a Identifier, so it requires special handling.
                    if child[2] == "NULL":
                        norm_cmp_value.append("NULL")
                    elif child[1] == "PrimaryExpression":
                        norm_cmp_value.append(child[2])
                    else:
                        norm_cmp_value.append("Var")
                        continue
        if xchild_id == 0:
            flag_left_value = True
        else:
            flag_left_value = False
        return self.unique_list(norm_cmp_items), norm_cmp_value, flag_left_value

    def query_check_patterns_path_thread(self, callee_id, callsite_id, path, controls_path, result, index):
        implicit_check_patterns, explicit_check_patterns = \
            self.query_check_patterns_path(callee_id, callsite_id, path, controls_path)

        result[index] = [implicit_check_patterns, explicit_check_patterns]
        return result

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

    # feature_callee = [    callee_id, 未使用前检查（0,1）,
    #                       [正确路径的路径数量,正确路径的语句数量，错误路径中使用返回值变量(1,0)],
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


    def run(self, flag_thread=True, *callee_from):
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
    #function_name ="snprintf"
    #function_name ="magic_compile"
    #function_name ="parse"
    function_name = INCOHERENT()

    extract_errfun_feature = ExtractErrFunFeatures(function_name)
    #patterns = extract_check_patterns.run(False, callee_ids)
    patterns = extract_errfun_feature.run(flag_thread=False)

    """
    flowlabel_code, operate_code, children = \
        extract_check_patterns.query_parsed_control(6638, 6651)
    """

    end_time = datetime.datetime.now()
    print "\nTime Used: %s (%s ~ %s)" % ((end_time - start_time), start_time, end_time)
