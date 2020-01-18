# coding:utf-8
# -----------------------------
# 编码作者：cl
# 更新时间：2019-12-05
# 模块功能：显示各个实例的行为向量的信息熵及其相关信息。
# -----------------------------

from database_provider import DBContentsProvider
from ObjDataAndBinFile import ObjDataAndBinFile

class DisplayEntropyInfo:
    def __init__(self, entropy):
        self.db_provider = DBContentsProvider()
        self.file_io_provider = ObjDataAndBinFile()
        self.entropy = entropy

    def run_gremlin_query(self, query):
        return self.db_provider.run_gremlin_query(query)

    def run_gremlin_query(self, query):
        return self.db_provider.run_gremlin_query(query)

    def query_loc_callsite(self, callee_id):
        query = """
            g.v(%s).statements.transform{[g.v(it.functionId).functionToFile.filepath, it.location]}
            """ % callee_id
        result = self.run_gremlin_query(query)
        loc = "%s: %s" % (result[0][0][0], result[0][1])
        return loc

    def display_entropy(self):
        sorted_entropy = self.sort_entropy()
        print "\n# Total entropy | implict-check | explict check | callsite id | location\n"
        for en in sorted_entropy:
            print en

    def sort_entropy(self):
        sorted_entropy = []
        for en in self.entropy:
            sum_entropy = sum(en[1])
            sum_entropy += sum(en[2])
            #sum_entropy = round(en[1][2] + en[2][2],2)
            sum_entropy = round(sum_entropy,2)
            loc = self.query_loc_callsite(en[0])
            sorted_entropy.append([sum_entropy, en[1], en[2], en[0], loc])
        sorted_entropy = sorted(sorted_entropy, key=lambda entropy: entropy[0], reverse=True)
        return sorted_entropy
