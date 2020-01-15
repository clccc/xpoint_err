#coding:utf-8
#-----------------------------
#code by Chenlin 2020-01-11 10:47:43
#功能: 将数据写入xls文件输出
#-----------------------------

import xlwt
import xlrd

class writeXLS:
    def __init__(self):

        return

    def new_xls(self,fp,userdata):
        writer = pd.ExcelWriter(fp)
        df = pd.DataFrame(data=userdata)
        df.to_excel(writer)
        writer.save()

    def write_excel(self,filename, data):
        book = xlwt.Workbook()            #创建excel对象
        sheet = book.add_sheet('PARTITIONS')  #添加一个表Sheet
        c = 0  #保存当前列
        for d in data: #取出data中的每一个元组存到表格的每一行
            #sheet.write(c,0,d[0])
            for index in range(len(d)):   #将每一个元组中的每一个单元存到每一列
                sheet.write(c,index,d[index])
            c += 1
        book.save(filename)