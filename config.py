# coding:utf-8
#-------------------------------
# 模块功能：统一设置算法参数
#-------------------------------


# 待识别函数列表
G_func_list = ['alloc_workqueue']

#一些奇怪的，暂时无法消除bug（与joern实现有关）的函数，不对此类函数进行处理，直接略过
G_func_unnormal = ['INCOHERENT','av_log','AVERROR','av_assert0','FFMIN',
                   'assert','RAND_pseudo_bytes','BN_rand_range','ECDSAerr',
                   'FAILED','likely','msg_Err','vlc_strerror_c']

# 待识别函数列表文件路径
# todo
G_func_path = ""

# 保存所有项源代码项目的识别数据的文件夹
G_alldata_dir = "Data"

# 保存单个具体源代码项目的识别结果的文件夹，*此处自动生成，无需修改*
G_prjdata_dir = ""
# 保存识别结果的文件路径,*此处自动生成，无需修改*
G_result_path = "%s/%s"%(G_prjdata_dir,"xp_err.txt")
# 保存中间调试信息的文件路径，*此处自动生成，无需修改*
G_debuginfo_path = "%s/%s"%(G_prjdata_dir,"degbug.txt")
G_result_xls = "%s/%s"%(G_prjdata_dir,"report.xls")
G_xcallee_xls = "%s/%s"%(G_prjdata_dir,"report.xls")
#以下为本算法的参数设定
#关于路径数量，语句数量“明显差异”的阈值，比例 > thld_path_ratio
G_thld_path_ratio = 2.0
G_thld_stmt_ratio = 2.0
#关于特征是否满足的阈值
G_thld_is_check = 0.7
G_thld_is_path = 0.5
G_thld_is_stmt = 0.5
G_thld_is_notuseTwosides = 0.7
#关于个性特征的危险系数，弃用优先级评估
#G_weight_path = 0.5
#G_weight_stmt = 0.5
#G_weight_useOneSide = 1
