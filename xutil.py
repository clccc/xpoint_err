# coding:utf-8
# -----------------------------
# code by cl in 2019-01-15
# 通用函数
# use Joern to extract err function (return-sensitive function)
# -----------------------------

import os
import math

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

def calculate_entropy(p, counts):
    h = 0
    h += p * math.log(p, 2)
    h = -h/math.log(counts, 10)
    return round(h, 2)