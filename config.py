# coding:utf-8
#-------------------------------
# 模块功能：统一设置算法参数
#-------------------------------

# 待识别函数列表
G_func_list = []

#一些奇怪的，暂时无法消除bug（与joern实现有关）的函数，不对此类函数进行处理，直接略过
G_func_unnormal = ['INCOHERENT']

# 待识别函数列表文件路径
G_func_path = ""

# 保存识别过程中特征信息的文件路径
# "Data/result_libtif407/%s.data"
G_feature_path = ""

# 保存识别结果的文件位置,不带/
G_result_locpath = ""

# 保存中间调试信息的文件路径
G_debug_path = "Data/degbug.txt"

#关于路径数量，语句数量“明显差异”的阈值，比例 > thld_path_ratio
G_thld_path_ratio = 2.0
G_thld_stmt_ratio = 2.0
#关于特征是否满足的阈值
G_thld_is_check = 0.8
G_thld_is_path = 0.8
G_thld_is_stmt = 0.8
G_thld_is_useOneside = 0.8
#关于个性特征的权重值
G_weight_path = 0.5
G_weight_stmt = 0.5
G_weight_useOneSide = 1
