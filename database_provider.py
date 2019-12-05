# ---------------------------
# 编码作者：cl
# 更新时间：2019-12-05
# 模块功能：为了调用便捷，封装Joern0.3.1中代码数据库链接功能，设定网络连接时限。
# ---------------------------
# coding:utf-8

from joern.all import JoernSteps
from py2neo.packages.httpstream import http
http.socket_timeout = 999999


class DBContentsProvider:

    def __init__(self):
        self.j = JoernSteps()
        self.init_database_connection()

    def init_database_connection(self):
        self.j.connectToDatabase()
        self.j.addStepsDir('steps/')

    def run_gremlin_query(self, query_script):
        results = self.j.runGremlinQuery(query_script)
        return results


if __name__ == '__main__':
    db_provider = DBContentsProvider()
    callee_name = "memset"
    query = 'getCallsTo(%s)._()' % callee_name
    query_result = db_provider.run_gremlin_query(query)
    for x in query_result:
        print x
