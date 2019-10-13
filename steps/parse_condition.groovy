//解析control，返回 真值，表达式id，表达式类型，逻辑运算符，表达式孩子节点信息（id，type，code）
Object.metaClass.parseControl= { control, nextCfgId ->
    try {
        //Protected code
        ids_child = g.v(control).outE('IS_AST_PARENT').inV.id.toList()
        if (ids_child.size() == 1){
            tpye_code = g.v(ids_child[0]).type
            operator_code = g.v(ids_child[0]).operator
        }

        flowlabel_code = _getFlowlabelOfCfgIds(control, nextCfgId)

        children = g.v(control).outE('IS_AST_PARENT').inV.out.transform{
            [it.id, it.type, it.code]
        }

        return [flowlabel_code, ids_child[0], tpye_code, operator_code, children]
    } catch(Exception ex) {
        //Catch block

        println "parseControl failed: " + ex
        println control
        println nextCfgId
    }

}

// Todo: is it right?
Object.metaClass._getFlowlabelOfCfgIds= { id_first, id_next ->
    try {
        edge = g.v(id_first).outE('FLOWS_TO').id.toList()
        // println edge.size()
        for (i = 0; i < edge.size(); i++) {
            if (g.e(edge[i]).inV.id._().toList()[0] == id_next) {
                // println g.e(edge[i]).flowLabel
                return g.e(edge[i]).flowLabel
            }
        }
        return 'Not found'
    } catch(Exception ex) {
        println "_getFlowlabelOfCfgIds failed: " + ex
        println id_first
        println id_next
    }
}

