# coding:utf-8
# ---------------------------
# 编码作者：cl
# 更新时间：2019-12-05
# 模块功能：使用pickle包将结构化数据存入文件或者从文件中读取出结构化数据
# ---------------------------

import pickle

class ObjDataAndBinFile:

    @staticmethod
    def objdata2file(data, filename):
        output = open(filename, 'wb')
        # Pickle dictionary using protocol 0.
        # pickle.dump(objData, output)

        # Pickle the list using the highest protocol available.
        pickle.dump(data, output, -1)
        output.close()

        # 使用pickle模块从文件中重构python对象
    @staticmethod
    def binfile2objdata(filename):
        pkl_file = open(filename, 'rb')
        data = pickle.load(pkl_file)
        pkl_file.close()
        return data
