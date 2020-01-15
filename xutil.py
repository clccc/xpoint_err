# coding:utf-8
# -----------------------------
# code by cl in 2019-01-15
# 通用函数
# use Joern to extract err function (return-sensitive function)
# -----------------------------

import os

def write_info(filepath, savedinfo):
    f= open(filepath,'a')
    print >> f,savedinfo
    # f.write(savedinfo)
    f.close()
    return

def make_dir(dir):
    isExists = os.path.exists(dir)
    if not isExists:
        os.makedirs(dir)
        result = "创建%s成功"%dir
    else:
        result = "检测%s已经存在"%dir
    return result